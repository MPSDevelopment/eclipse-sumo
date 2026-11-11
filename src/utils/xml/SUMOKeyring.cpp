/****************************************************************************/
// Eclipse SUMO, Simulation of Urban MObility; see https://eclipse.dev/sumo
// Copyright (C) 2026 MPS Development.
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// https://www.eclipse.org/legal/epl-2.0/
// This Source Code may also be made available under the following Secondary
// Licenses when the conditions for such availability set forth in the Eclipse
// Public License 2.0 are satisfied: GNU General Public License, version 2
// or later which is available at
// https://www.gnu.org/licenses/old-licenses/gpl-2.0-standalone.html
// SPDX-License-Identifier: EPL-2.0 OR GPL-2.0-or-later
/****************************************************************************/
/// @file    SUMOKeyring.cpp
/// @date    Nov 2026
///
// Per-file AES-256-GCM keys for encrypted input files
/****************************************************************************/
#include <config.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <vector>

#include <utils/common/StdDefs.h>
#include <utils/common/UtilExceptions.h>
#include <utils/xml/XMLSubSys.h>
#ifdef HAVE_ZLIB
#include <foreign/zstr/zstr.hpp>
#endif
#include "SUMOKeyring.h"

#ifdef HAVE_KEYRING
#include <filesystem>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#ifdef HAVE_ZLIB
#include <zlib.h>
#endif
#ifdef WIN32
#include <windows.h>
#else
#include <cerrno>
#include <unistd.h>
#endif
#endif


#ifdef HAVE_KEYRING
namespace {

const char KEYRING_MAGIC[4] = {'D', 'K', 'R', '1'};
const size_t GCM_TAG_SIZE = 16;
const uint32_t MAX_ENTRIES = 256;
const uint16_t MAX_PATH_LENGTH = 1024;
const size_t MAX_PLAINTEXT_SIZE = size_t(512) << 20;

struct Entry {
    std::string relativePath;
    std::array<unsigned char, 32> key;
    std::array<unsigned char, 12> nonce;
};

std::map<std::string, Entry> gEntries;
bool gRequired = false;


void
cleanse(Entry& entry) {
    OPENSSL_cleanse(entry.key.data(), entry.key.size());
    OPENSSL_cleanse(entry.nonce.data(), entry.nonce.size());
}


bool
readBytes(std::istream& in, void* out, size_t size) {
    in.read(static_cast<char*>(out), static_cast<std::streamsize>(size));
    return static_cast<size_t>(in.gcount()) == size;
}


bool
readU16(std::istream& in, uint16_t& value) {
    unsigned char b[2];
    if (!readBytes(in, b, sizeof(b))) {
        return false;
    }
    value = static_cast<uint16_t>((b[0] << 8) | b[1]);
    return true;
}


bool
readU32(std::istream& in, uint32_t& value) {
    unsigned char b[4];
    if (!readBytes(in, b, sizeof(b))) {
        return false;
    }
    value = (static_cast<uint32_t>(b[0]) << 24) | (static_cast<uint32_t>(b[1]) << 16)
            | (static_cast<uint32_t>(b[2]) << 8) | static_cast<uint32_t>(b[3]);
    return true;
}


std::filesystem::path
toPath(const std::string& utf8Path) {
#ifdef __cpp_char8_t
    return std::filesystem::path(std::u8string(utf8Path.begin(), utf8Path.end()));
#else
    return std::filesystem::u8path(utf8Path);
#endif
}


std::string
normalize(const std::string& utf8Path) {
    std::error_code ec;
    const std::filesystem::path canonical = std::filesystem::canonical(toPath(utf8Path), ec);
    if (ec) {
        return "";
    }
    // u8string() is std::string before C++20 and std::u8string after
    const auto utf8 = canonical.u8string();
    std::string normalized(utf8.begin(), utf8.end());
#ifdef WIN32
    for (char& c : normalized) {
        if (c == '\\') {
            c = '/';
        } else if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
#endif
    return normalized;
}


// Reads the frame straight from the OS in exactly the sizes asked for, so no C or C++ runtime stdin buffer keeps a
// copy of the file keys after clear().
class RawStdinBuf : public std::streambuf {
protected:
    std::streamsize xsgetn(char* s, std::streamsize n) override {
        std::streamsize total = 0;
        while (total < n) {
#ifdef WIN32
            DWORD chunk = 0;
            const DWORD want = static_cast<DWORD>(std::min<std::streamsize>(n - total, 1 << 20));
            if (!ReadFile(GetStdHandle(STD_INPUT_HANDLE), s + total, want, &chunk, nullptr) || chunk == 0) {
                break;
            }
#else
            const ssize_t chunk = read(STDIN_FILENO, s + total, static_cast<size_t>(n - total));
            if (chunk < 0 && errno == EINTR) {
                continue;
            }
            if (chunk <= 0) {
                break;
            }
#endif
            total += chunk;
        }
        return total;
    }

    int_type underflow() override {
        return traits_type::eof();
    }
};


#ifdef WIN32
// Run-time DLL loads search System32 only, never the executable's or the working folder. Static imports are
// resolved by the loader before main() and are not affected; they are pinned by hash in the release instead.
void
restrictDllSearchPath() {
    typedef BOOL (WINAPI * SetDefaultDllDirectoriesFn)(DWORD);
    const DWORD LOAD_LIBRARY_SEARCH_SYSTEM32_FLAG = 0x00000800;
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC proc = kernel32 ? GetProcAddress(kernel32, "SetDefaultDllDirectories") : nullptr;
    if (proc) {
        reinterpret_cast<SetDefaultDllDirectoriesFn>(reinterpret_cast<void*>(proc))(LOAD_LIBRARY_SEARCH_SYSTEM32_FLAG);
    }
    SetDllDirectoryW(L"");
}
#endif


class PlaintextBuf : public std::streambuf {
public:
    explicit PlaintextBuf(std::vector<char>& data) {
        setg(data.data(), data.data(), data.data() + data.size());
    }

protected:
    pos_type seekoff(off_type off, std::ios_base::seekdir dir, std::ios_base::openmode which) override {
        if ((which & std::ios_base::in) == 0) {
            return pos_type(off_type(-1));
        }
        off_type target = off;
        if (dir == std::ios_base::cur) {
            target += gptr() - eback();
        } else if (dir == std::ios_base::end) {
            target += egptr() - eback();
        }
        if (target < 0 || target > egptr() - eback()) {
            return pos_type(off_type(-1));
        }
        setg(eback(), eback() + target, egptr());
        return pos_type(target);
    }

    pos_type seekpos(pos_type pos, std::ios_base::openmode which) override {
        return seekoff(off_type(pos), std::ios_base::beg, which);
    }
};


class PlaintextStream : public std::istream {
public:
    explicit PlaintextStream(std::vector<char>&& data) :
        std::istream(nullptr), myData(std::move(data)), myBuf(myData) {
        rdbuf(&myBuf);
    }

    ~PlaintextStream() override {
        rdbuf(nullptr);
        OPENSSL_cleanse(myData.data(), myData.size());
    }

private:
    std::vector<char> myData;
    PlaintextBuf myBuf;
};


#ifdef HAVE_ZLIB
// Grows by copying into a new buffer and wiping the old one, so a reallocation leaves no plaintext behind.
void
growSecure(std::vector<char>& buf, size_t used, size_t newSize) {
    std::vector<char> bigger(newSize);
    std::memcpy(bigger.data(), buf.data(), used);
    OPENSSL_cleanse(buf.data(), buf.size());
    buf.swap(bigger);
}


// Inflates a gzip file (possibly several members) in memory; the result is capped like plain files.
bool
gunzip(const std::vector<char>& in, std::vector<char>& out) {
    z_stream zs;
    std::memset(&zs, 0, sizeof(zs));
    if (inflateInit2(&zs, 15 + 16) != Z_OK) {
        return false;
    }
    // the gzip trailer holds the size of the (last member's) data modulo 2^32, a good first guess
    size_t hint = 0;
    if (in.size() >= 18) {
        const unsigned char* tail = reinterpret_cast<const unsigned char*>(in.data() + in.size() - 4);
        hint = size_t(tail[0]) | size_t(tail[1]) << 8 | size_t(tail[2]) << 16 | size_t(tail[3]) << 24;
    }
    out.assign(std::min(MAX_PLAINTEXT_SIZE, std::max<size_t>(hint + 1, 1 << 16)), '\0');
    size_t used = 0;
    zs.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));
    zs.avail_in = static_cast<uInt>(in.size());
    bool done = false;
    while (true) {
        if (used == out.size()) {
            if (out.size() >= MAX_PLAINTEXT_SIZE) {
                break;
            }
            growSecure(out, used, std::min(MAX_PLAINTEXT_SIZE, out.size() * 2));
        }
        zs.next_out = reinterpret_cast<Bytef*>(out.data() + used);
        zs.avail_out = static_cast<uInt>(out.size() - used);
        const int rc = inflate(&zs, Z_NO_FLUSH);
        used = out.size() - zs.avail_out;
        if (rc == Z_STREAM_END) {
            if (zs.avail_in == 0) {
                done = true;
                break;
            }
            if (inflateReset(&zs) != Z_OK) {
                break;
            }
        } else if (rc == Z_BUF_ERROR) {
            if (zs.avail_in == 0) {
                break;
            }
        } else if (rc != Z_OK) {
            break;
        }
    }
    inflateEnd(&zs);
    if (!done) {
        OPENSSL_cleanse(out.data(), out.size());
        out.clear();
        return false;
    }
    out.resize(used);
    return true;
}
#endif


std::unique_ptr<std::istream>
decrypt(const std::string& file, const Entry& entry) {
    std::ifstream in(toPath(file), std::ios::in | std::ios::binary);
    if (!in.is_open()) {
        throw ProcessError("Could not open encrypted file '" + file + "'.");
    }
    in.seekg(0, std::ios::end);
    const std::streamoff fileSize = in.tellg();
    in.seekg(0, std::ios::beg);
    if (fileSize < 0 || !in) {
        throw ProcessError("Could not read encrypted file '" + file + "'.");
    }
    if (static_cast<unsigned long long>(fileSize) > MAX_PLAINTEXT_SIZE + GCM_TAG_SIZE) {
        throw ProcessError("Encrypted file '" + file + "' is too large.");
    }
    if (static_cast<size_t>(fileSize) < GCM_TAG_SIZE) {
        throw ProcessError("Encrypted file '" + file + "' is too short.");
    }
    std::vector<unsigned char> data(static_cast<size_t>(fileSize));
    if (!readBytes(in, data.data(), data.size())) {
        throw ProcessError("Could not read encrypted file '" + file + "'.");
    }
    const size_t cipherLen = data.size() - GCM_TAG_SIZE;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        throw ProcessError("Could not decrypt '" + file + "'.");
    }
    std::vector<char> plaintext(cipherLen + 1);
    unsigned char* const out = reinterpret_cast<unsigned char*>(plaintext.data());
    int len = 0;
    int total = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1
              && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(entry.nonce.size()), nullptr) == 1
              && EVP_DecryptInit_ex(ctx, nullptr, nullptr, entry.key.data(), entry.nonce.data()) == 1
              && EVP_DecryptUpdate(ctx, nullptr, &len,
                                   reinterpret_cast<const unsigned char*>(entry.relativePath.data()),
                                   static_cast<int>(entry.relativePath.size())) == 1;
    if (ok && cipherLen > 0) {
        ok = EVP_DecryptUpdate(ctx, out, &len, data.data(), static_cast<int>(cipherLen)) == 1;
        total = len;
    }
    ok = ok
         && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(GCM_TAG_SIZE), data.data() + cipherLen) == 1
         && EVP_DecryptFinal_ex(ctx, out + total, &len) == 1;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        throw ProcessError("Could not decrypt '" + file + "'.");
    }
    // shrinking never reallocates, so no copy of the plaintext is left behind
    plaintext.resize(static_cast<size_t>(total + len));
#ifdef HAVE_ZLIB
    if (plaintext.size() >= 2 && static_cast<unsigned char>(plaintext[0]) == 0x1f
            && static_cast<unsigned char>(plaintext[1]) == 0x8b) {
        std::vector<char> inflated;
        const bool inflatedOk = gunzip(plaintext, inflated);
        OPENSSL_cleanse(plaintext.data(), plaintext.size());
        if (!inflatedOk) {
            throw ProcessError("Could not decompress encrypted file '" + file + "'.");
        }
        return std::unique_ptr<std::istream>(new PlaintextStream(std::move(inflated)));
    }
#endif
    return std::unique_ptr<std::istream>(new PlaintextStream(std::move(plaintext)));
}

}
#endif


// ===========================================================================
// method definitions
// ===========================================================================
bool
SUMOKeyring::initFromArgs(int& argc, char** argv, bool required) {
    bool keyringStdin = false;
    int kept = 1;
    for (int i = 1; i < argc; i++) {
        if (std::strcmp(argv[i], "--keyring-stdin") == 0) {
            keyringStdin = true;
        } else {
            argv[kept++] = argv[i];
        }
    }
    argc = kept;
    argv[argc] = nullptr;
#ifdef HAVE_KEYRING
    gRequired = required;
#ifdef WIN32
    if (required) {
        restrictDllSearchPath();
    }
#endif
    if (required && !keyringStdin) {
        std::cerr << "keyring required" << std::endl;
        return false;
    }
    if (keyringStdin) {
        RawStdinBuf rawStdin;
        std::istream in(&rawStdin);
        if (!readFrom(in)) {
            std::cerr << "invalid keyring" << std::endl;
            return false;
        }
    }
    return true;
#else
    if (required || keyringStdin) {
        std::cerr << "keyring not supported by this build" << std::endl;
        return false;
    }
    return true;
#endif
}


bool
SUMOKeyring::readFrom(std::istream& in) {
#ifdef HAVE_KEYRING
    clear();
    // Before any other OpenSSL call: a config file (OPENSSL_CONF or the compiled-in OPENSSLDIR) could otherwise load
    // provider modules into this process.
    if (!OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, nullptr)) {
        return false;
    }
    char magic[sizeof(KEYRING_MAGIC)];
    uint32_t count = 0;
    bool ok = readBytes(in, magic, sizeof(magic))
              && std::equal(std::begin(magic), std::end(magic), std::begin(KEYRING_MAGIC))
              && readU32(in, count)
              && count <= MAX_ENTRIES;
    Entry entry;
    for (uint32_t i = 0; ok && i < count; ++i) {
        uint16_t pathLen = 0;
        ok = readU16(in, pathLen) && pathLen > 0 && pathLen <= MAX_PATH_LENGTH;
        if (!ok) {
            break;
        }
        entry.relativePath.assign(pathLen, '\0');
        ok = readBytes(in, &entry.relativePath[0], pathLen)
             && readBytes(in, entry.key.data(), entry.key.size())
             && readBytes(in, entry.nonce.data(), entry.nonce.size());
        if (!ok) {
            break;
        }
        const std::string normalized = normalize(entry.relativePath);
        ok = !normalized.empty();
        if (ok) {
            Entry& stored = gEntries[normalized];
            cleanse(stored);
            stored = entry;
        }
    }
    cleanse(entry);
    if (!ok) {
        clear();
    }
    return ok;
#else
    UNUSED_PARAMETER(in);
    return false;
#endif
}


void
SUMOKeyring::clear() {
#ifdef HAVE_KEYRING
    for (auto& item : gEntries) {
        cleanse(item.second);
    }
    gEntries.clear();
#endif
}


bool
SUMOKeyring::isRequired() {
#ifdef HAVE_KEYRING
    return gRequired;
#else
    return false;
#endif
}


std::unique_ptr<std::istream>
SUMOKeyring::open(const std::string& file) {
#ifdef HAVE_KEYRING
    if (!gEntries.empty() || gRequired) {
        const auto it = gEntries.find(normalize(file));
        if (it != gEntries.end()) {
            return decrypt(file, it->second);
        }
        if (gRequired) {
            throw ProcessError("File '" + file + "' has no key in the keyring.");
        }
    }
#endif
#ifdef HAVE_ZLIB
    return std::unique_ptr<std::istream>(new zstr::ifstream(XMLSubSys::transcodeToLocal(file).c_str(), std::fstream::in | std::fstream::binary));
#else
    return std::unique_ptr<std::istream>(new std::ifstream(XMLSubSys::transcodeToLocal(file).c_str(), std::fstream::in | std::fstream::binary));
#endif
}
