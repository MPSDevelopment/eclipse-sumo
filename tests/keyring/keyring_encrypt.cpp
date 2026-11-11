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
/// @file    keyring_encrypt.cpp
/// @date    Nov 2026
///
// Test helper: encrypts files and writes the keyring frame the way DARTS's
// ContentKeyring does (big-endian "DKR1", u32 count, per file u16 path length,
// UTF-8 path, key[32], nonce[12]; ciphertext followed by the 16-byte GCM tag,
// AAD = the path as written in the frame).
//
// usage: keyring_encrypt <frame-out> (<frame-path> <plain-in> <encrypted-out>)...
/****************************************************************************/
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>


static void
putU16(std::vector<unsigned char>& out, uint16_t v) {
    out.push_back(static_cast<unsigned char>(v >> 8));
    out.push_back(static_cast<unsigned char>(v));
}


static void
putU32(std::vector<unsigned char>& out, uint32_t v) {
    for (int shift = 24; shift >= 0; shift -= 8) {
        out.push_back(static_cast<unsigned char>(v >> shift));
    }
}


static bool
encrypt(const std::string& aad, const std::vector<unsigned char>& plain, const unsigned char* key,
        const unsigned char* nonce, std::vector<unsigned char>& out) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    out.assign(plain.size() + 16, 0);
    int len = 0;
    int total = 0;
    bool ok = ctx != nullptr
              && EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1
              && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1
              && EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) == 1
              && EVP_EncryptUpdate(ctx, nullptr, &len, reinterpret_cast<const unsigned char*>(aad.data()),
                                   static_cast<int>(aad.size())) == 1;
    if (ok && !plain.empty()) {
        ok = EVP_EncryptUpdate(ctx, out.data(), &len, plain.data(), static_cast<int>(plain.size())) == 1;
        total = len;
    }
    ok = ok && EVP_EncryptFinal_ex(ctx, out.data() + total, &len) == 1
         && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out.data() + plain.size()) == 1;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}


int
main(int argc, char** argv) {
    if (argc < 5 || (argc - 2) % 3 != 0) {
        std::cerr << "usage: keyring_encrypt <frame-out> (<frame-path> <plain-in> <encrypted-out>)..." << std::endl;
        return 2;
    }
    std::vector<unsigned char> frame = {'D', 'K', 'R', '1'};
    putU32(frame, static_cast<uint32_t>((argc - 2) / 3));
    for (int i = 2; i < argc; i += 3) {
        const std::string path = argv[i];
        std::ifstream in(argv[i + 1], std::ios::binary);
        if (!in) {
            std::cerr << "cannot read " << argv[i + 1] << std::endl;
            return 2;
        }
        const std::vector<unsigned char> plain((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        unsigned char key[32];
        unsigned char nonce[12];
        std::vector<unsigned char> cipher;
        if (RAND_bytes(key, sizeof(key)) != 1 || RAND_bytes(nonce, sizeof(nonce)) != 1
                || !encrypt(path, plain, key, nonce, cipher)) {
            std::cerr << "encryption failed" << std::endl;
            return 2;
        }
        std::ofstream out(argv[i + 2], std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(cipher.data()), static_cast<std::streamsize>(cipher.size()));
        if (!out) {
            std::cerr << "cannot write " << argv[i + 2] << std::endl;
            return 2;
        }
        putU16(frame, static_cast<uint16_t>(path.size()));
        frame.insert(frame.end(), path.begin(), path.end());
        frame.insert(frame.end(), key, key + sizeof(key));
        frame.insert(frame.end(), nonce, nonce + sizeof(nonce));
    }
    std::ofstream out(argv[1], std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(frame.data()), static_cast<std::streamsize>(frame.size()));
    return out ? 0 : 2;
}
