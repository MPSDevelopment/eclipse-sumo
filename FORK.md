# MPSDevelopment fork of Eclipse SUMO

Upstream: https://github.com/eclipse-sumo/sumo. This fork adds encrypted input files for DARTS (UAV Simulator)
and nothing else. Licence unchanged: EPL-2.0 (or GPL-2.0-or-later), see `LICENSE` and `NOTICE.md`.

## Keyring (`--keyring-stdin`)

`sumo --keyring-stdin ...` reads a binary keyring frame from stdin before anything else, in the same format as the
MPSDevelopment JSBSim fork (`FGKeyring`), big-endian:

```
"DKR1"  u32 count
count x ( u16 pathLength  UTF-8 path  key[32]  nonce[12] )
```

- at most 256 entries, path length 1..1024 bytes; a later entry for the same file replaces an earlier one
- the path is relative to the working directory (forward slashes) and is matched against every input file after
  both are made canonical (Windows: also lower-cased, `\` -> `/`)
- an encrypted file keeps its name and place on disk; it holds AES-256-GCM ciphertext followed by the 16-byte tag,
  AAD = the path exactly as written in the frame
- if the decrypted bytes start with the gzip magic they are inflated in memory, so a `.net.xml.gz` is encrypted
  as stored (compress first, then encrypt)
- at most 512 MiB of plaintext per file (after inflating)
- a bad frame exits 1 with `invalid keyring`; a tampered file or wrong key fails the load (`Could not decrypt '<file>'.`,
  exit 1)
- the keyring is kept for the whole run (additional files are parsed twice, TraCI `load` re-reads files); plaintext
  exists only in memory and is wiped (`OPENSSL_cleanse`) when the reader's stream is released
- the frame is read straight from the OS (`read`/`ReadFile`), not through a C/C++ stdin buffer

Every XML input goes through `SUMOKeyring::open` (`src/utils/xml/SUMOKeyring.*`): `SUMOSAXReader::parse` and
`parseFirst` (all `XMLSubSys::runParser` users, including `ShapeHandler::loadFiles`, route and state loading) and
`OptionsIO` (configuration files). Files without a key are read as before (zstr, gzip aware). Only `sumo` handles
the flag; `sumo-gui`, `netconvert` and the other tools are unchanged.

CMake options:

- `SUMO_KEYRING` (default ON): links OpenSSL 3 libcrypto into `utils_xml`, defines `HAVE_KEYRING`
- `SUMO_HARDENED` (default OFF, ON in the release build): only for the `sumo` target. It refuses to start without
  `--keyring-stdin` (`keyring required`, exit 1) and refuses every XML input file that has no key
  (`File '<file>' has no key in the keyring.`). It also:
  - binds the TraCI server to 127.0.0.1 only (`tcpip::Socket` listens on its host when one is given),
  - answers TraCI `load` (CMD_LOAD) and `simulation.saveState` with a TraCI error (`... is disabled in this build.`),
  - accepts only an allowlist of options (`HardenedOptions`, `src/utils/options`). Every option set to a
    non-default value, on the command line or in the `.sumocfg`, must be one of: configuration-file, net-file,
    route-files, additional-files, remote-port, num-clients (1 only), step-length, begin, end, seed, random,
    time-to-teleport, collision.action, collision.check-junctions, default.speeddev, ignore-route-errors,
    max-depart-delay, no-step-log, no-warnings, verbose (off only), duration-log.disable, log, message-log,
    error-log (`--keyring-stdin` is consumed before option parsing). Anything else exits 1 with
    `Option '--<name>' is not allowed in this hardened build.` Add an option only on purpose, after checking that
    it cannot write a file or expose the decrypted input,
  - on Windows restricts run-time DLL loading to System32 (`SetDefaultDllDirectories`, as in the JSBSim fork); the
    DLLs next to sumo.exe are static imports and are pinned by hash (`SHA256SUMS` lists every shipped file).

  sumo-gui and netconvert from the same build stay plain.

## Tests

`tests/keyring/` (ctest label `keyring`): `keyring_encrypt` writes encrypted files and the frame like DARTS's
`ContentKeyring`, `run_keyring_test.py` runs the cases. Non-hardened-only and hardened-only cases report as skipped
in the other build.

```
cmake -S . -B build-keyring -G Ninja -DISOLATED_BUILD=ON -DCMAKE_BUILD_TYPE=Release -DENABLE_FOX=OFF \
  -DCHECK_OPTIONAL_LIBS=OFF -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
ninja -C build-keyring sumo keyring_encrypt && (cd build-keyring && ctest -L keyring)
# same again with -B build-hardened -DSUMO_HARDENED=ON
```

## Release

`.github/workflows/mps-release.yml` runs on every push to `main` (and manually): Windows (MSVC, SUMOLibraries release zip checked against a sha256 in
the workflow, static OpenSSL from vcpkg pinned to a commit, `x64-windows-static-md`; all actions pinned by commit SHA) builds hardened `sumo.exe`, plain `sumo-gui.exe` and
`netconvert.exe`; Linux (ubuntu-22.04) builds hardened `sumo` with static libcrypto (still needs the system
`libxerces-c`, `libproj`, zlib; see `linux/shared-libraries.txt` in the zip). Both run the keyring tests. The release
`mps-<run>` holds one zip with `windows/`, `linux/`, `third-party/` licences, `LICENSE-EPL-2.0.txt`, `NOTICE.md`,
this file and `SHA256SUMS`.

The upstream workflows (`windows.yml`, `linux.yml`, `macos.yml`, ...) still exist and run on pushes; disable them in
the repository's Actions settings if the CI minutes matter.

## Rebasing onto upstream

The patch is kept small on purpose. Fork-only files: `src/utils/xml/SUMOKeyring.{h,cpp}`, `src/utils/options/HardenedOptions.{h,cpp}`, `tests/keyring/`,
`.github/workflows/mps-release.yml`, `FORK.md`. Touched upstream files (a few lines each):

- `CMakeLists.txt`: the two options, `find_package(OpenSSL)`, `add_subdirectory(tests/keyring)`
- `src/CMakeLists.txt`: `SUMO_HARDENED` define on the `sumo` target
- `src/utils/xml/CMakeLists.txt`: source list, link `OpenSSL::Crypto`
- `src/utils/xml/SUMOSAXReader.cpp`: `zstr::ifstream` -> `SUMOKeyring::open` in `parse` and `parseFirst`
- `src/utils/options/OptionsIO.cpp`: same in `loadConfiguration` and `getRoot`
- `src/sumo_main.cpp`: `SUMOKeyring::initFromArgs` at the start of `main`
- `src/netload/NLBuilder.cpp`: `HardenedOptions::check` (allowlist) after option parsing
- `src/traci-server/TraCIServer.cpp`, `TraCIServerAPI_Simulation.cpp`: loopback server socket, CMD_LOAD and
  saveState refusal
- `src/foreign/tcpip/socket.cpp`: listen address from `host_`
- `src/utils/options/CMakeLists.txt`: `HardenedOptions` sources

```
git remote add upstream https://github.com/eclipse-sumo/sumo.git
git fetch upstream main
git rebase upstream/main      # conflicts, if any, are in the files above
```

After a rebase, new upstream options are refused by default in hardened builds (allowlist), so nothing has to be
done for them unless DARTS needs one. Still grep for new file readers that bypass the keyring (`zstr::ifstream`, `parser.parse(`,
`LocalFileInputSource`) under `src/utils` and `src/netload`, and rerun the keyring tests in both builds.
