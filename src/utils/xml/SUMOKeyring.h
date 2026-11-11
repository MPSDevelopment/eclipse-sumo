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
/// @file    SUMOKeyring.h
/// @date    Nov 2026
///
// Per-file AES-256-GCM keys for encrypted input files
/****************************************************************************/
#pragma once
#include <config.h>

#include <istream>
#include <memory>
#include <string>


/**
 * @class SUMOKeyring
 * @brief Holds the per-file keys used to decrypt encrypted XML input files
 *
 * The keyring is read once from a binary frame on stdin (big-endian):
 * "DKR1", u32 count, then per entry: u16 path length, UTF-8 path relative to
 * the working directory (forward slashes), 32-byte AES-256 key, 12-byte GCM
 * nonce. A frame holds at most 256 entries and a path is 1 to 1024 bytes long;
 * a later entry for the same file replaces an earlier one. This is the frame
 * of the MPSDevelopment JSBSim fork (FGKeyring).
 *
 * An encrypted file holds ciphertext followed by the 16-byte GCM tag; the
 * additional authenticated data is the entry's path exactly as written in the
 * frame. The file stays at its path on disk and is decrypted into memory only;
 * decrypted gzip data is inflated in memory as well.
 */
class SUMOKeyring {
public:
    /** @brief Handles --keyring-stdin for an application main
     *
     * Removes the flag from argv and, when present, reads the keyring from stdin.
     * With required set (hardened build) the flag is mandatory and every input
     * file needs a key. Prints "keyring required" or "invalid keyring" to stderr
     * and returns false when the application has to exit with 1.
     */
    static bool initFromArgs(int& argc, char** argv, bool required);

    /// @brief reads a keyring frame, replacing the current keys; false on an invalid frame
    static bool readFrom(std::istream& in);

    /// @brief wipes all keys
    static void clear();

    /// @brief whether every input file must have a key
    static bool isRequired();

    /** @brief Opens an XML input file for reading
     *
     * A file with a key is decrypted into memory; otherwise the file is opened
     * as before (gzip aware when zlib is available).
     * @throw ProcessError if the file has no key but keys are required, or decryption fails
     */
    static std::unique_ptr<std::istream> open(const std::string& file);
};
