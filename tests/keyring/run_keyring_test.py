#!/usr/bin/env python3
# Eclipse SUMO, Simulation of Urban MObility; see https://eclipse.dev/sumo
# Copyright (C) 2026 MPS Development.
# This program and the accompanying materials are made available under the
# terms of the Eclipse Public License 2.0 which is available at
# https://www.eclipse.org/legal/epl-2.0/
# This Source Code may also be made available under the following Secondary
# Licenses when the conditions for such availability set forth in the Eclipse
# Public License 2.0 are satisfied: GNU General Public License, version 2
# or later which is available at
# https://www.gnu.org/licenses/old-licenses/gpl-2.0-standalone.html
# SPDX-License-Identifier: EPL-2.0 OR GPL-2.0-or-later

"""Runs one keyring test case against a sumo binary (ctest driver)."""

import argparse
import gzip
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid

FILES = ["net.net.xml", "routes.rou.xml", "shapes.add.xml", "run.sumocfg"]
BASE_ARGS = ["--no-step-log", "--end", "100"]
# hardened sumo refuses options DARTS does not use, statistics included
STATS_ARGS = ["--duration-log.statistics"]
CASES = {}
TOOLS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tools")


def case(hardened=None):
    def register(fn):
        CASES[fn.__name__] = (fn, hardened)
        return fn
    return register


class Env:
    def __init__(self, args):
        self.sumo = args.sumo
        self.encrypt = args.encrypt
        self.data = args.data
        self.work = tempfile.mkdtemp(prefix="sumo-keyring-")
        self.marker = "PLAINTEXT-MARKER-" + uuid.uuid4().hex
        self.compressed = []

    def plain(self, name):
        shutil.copy(os.path.join(self.data, name), os.path.join(self.work, name))

    def encrypted(self, names, gzipped=(), frame="keyring.bin"):
        """Encrypts the data files into the work dir; the plaintext (with a per-run marker) exists only in a
        separate folder that is deleted before sumo runs. Files in gzipped are stored as <name>.gz, compressed
        before encryption like the shipped traffic nets."""
        src = tempfile.mkdtemp(prefix="sumo-keyring-src-")
        cmd = [self.encrypt, os.path.join(src, frame)]
        try:
            for name in names:
                with open(os.path.join(self.data, name), "rb") as f:
                    content = f.read()
                decl_end = content.index(b"?>") + 2 if content.startswith(b"<?xml") else 0
                content = content[:decl_end] + ("<!-- %s -->" % self.marker).encode() + content[decl_end:]
                if name in gzipped:
                    content = gzip.compress(content)
                    self.compressed.append(content)
                    name += ".gz"
                with open(os.path.join(src, name), "wb") as f:
                    f.write(content)
                cmd += [name, os.path.join(src, name), os.path.join(self.work, name)]
            subprocess.check_call(cmd)
            with open(os.path.join(src, frame), "rb") as f:
                return f.read()
        finally:
            shutil.rmtree(src)

    def base_args(self):
        return BASE_ARGS if self.hardened else BASE_ARGS + STATS_ARGS

    def run(self, args, stdin=None):
        proc = subprocess.run([self.sumo] + args + self.base_args(), cwd=self.work, input=stdin,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
        out = proc.stdout.decode(errors="replace") + proc.stderr.decode(errors="replace")
        print("$ sumo %s -> exit %s\n%s" % (" ".join(args), proc.returncode, out))
        return proc.returncode, out

    def start(self, args, stdin=None):
        proc = subprocess.Popen([self.sumo] + args + self.base_args(), cwd=self.work, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if stdin is not None:
            proc.stdin.write(stdin)
        proc.stdin.close()
        # Python 3.10's communicate() flushes a closed stdin pipe (ValueError); later versions skip it
        proc.stdin = None
        return proc

    def finish(self, proc, kill=False):
        if kill and proc.poll() is None:
            proc.kill()
        try:
            out = proc.communicate(timeout=60)[0]
        except subprocess.TimeoutExpired:
            proc.kill()
            out = proc.communicate()[0]
        out = out.decode(errors="replace")
        print("sumo exit %s\n%s" % (proc.returncode, out))
        return proc.returncode, out

    def cleanup(self):
        shutil.rmtree(self.work, ignore_errors=True)


def expect(cond, message):
    if not cond:
        raise AssertionError(message)


def expect_ran(code, out):
    expect(code == 0, "sumo exited with %s" % code)
    expect("Error" not in out, "sumo reported an error")
    if "Inserted:" in out:
        expect("Inserted: 1" in out, "the vehicle was not inserted")


def expect_failed(code, out, text):
    expect(code != 0, "sumo should have failed")
    expect(text in out, "missing error text %r" % text)


def flip_byte(path, offset):
    with open(path, "r+b") as f:
        f.seek(offset)
        b = f.read(1)
        f.seek(offset)
        f.write(bytes([b[0] ^ 0x01]))


def scan_for_marker(env, roots, since):
    hits = []
    for root in roots:
        for dirpath, _, files in os.walk(root):
            for name in files:
                path = os.path.join(dirpath, name)
                try:
                    if os.path.getmtime(path) < since:
                        continue
                    with open(path, "rb") as f:
                        content = f.read()
                    if env.marker.encode() in content or any(c in content for c in env.compressed):
                        hits.append(path)
                except OSError:
                    pass
    return hits


@case(hardened=False)
def plain_loads(env):
    for name in FILES[:3]:
        env.plain(name)
    expect_ran(*env.run(["-n", "net.net.xml", "-r", "routes.rou.xml", "-a", "shapes.add.xml"]))


@case()
def encrypted_loads(env):
    frame = env.encrypted(FILES[:3])
    expect_ran(*env.run(["--keyring-stdin", "-n", "net.net.xml", "-r", "routes.rou.xml", "-a", "shapes.add.xml"],
                        frame))


@case()
def encrypted_config_loads(env):
    frame = env.encrypted(FILES)
    expect_ran(*env.run(["--keyring-stdin", "-c", "run.sumocfg"], frame))


@case()
def no_plaintext_on_disk(env):
    since = time.time() - 1
    frame = env.encrypted(FILES[:3])
    expect_ran(*env.run(["--keyring-stdin", "-n", "net.net.xml", "-r", "routes.rou.xml", "-a", "shapes.add.xml"],
                        frame))
    with open(os.path.join(env.work, "net.net.xml"), "rb") as f:
        expect(b"<net" not in f.read(), "the net file on disk is not encrypted")
    roots = {env.work, tempfile.gettempdir(), os.path.expanduser("~/.sumo")}
    hits = scan_for_marker(env, [r for r in roots if os.path.isdir(r)], since)
    expect(not hits, "plaintext found on disk: %s" % hits)


@case()
def encrypted_gzip_net_loads(env):
    since = time.time() - 1
    frame = env.encrypted(FILES[:2], gzipped=("net.net.xml",))
    expect_ran(*env.run(["--keyring-stdin", "-n", "net.net.xml.gz", "-r", "routes.rou.xml"], frame))
    with open(os.path.join(env.work, "net.net.xml.gz"), "rb") as f:
        expect(not f.read().startswith(b"\x1f\x8b"), "the net file on disk is not encrypted")
    roots = {env.work, tempfile.gettempdir(), os.path.expanduser("~/.sumo")}
    hits = scan_for_marker(env, [r for r in roots if os.path.isdir(r)], since)
    expect(not hits, "plaintext found on disk: %s" % hits)


@case()
def tampered_gzip_net_fails(env):
    frame = env.encrypted(FILES[:2], gzipped=("net.net.xml",))
    flip_byte(os.path.join(env.work, "net.net.xml.gz"), 50)
    expect_failed(*env.run(["--keyring-stdin", "-n", "net.net.xml.gz", "-r", "routes.rou.xml"], frame),
                  "Could not decrypt")


@case()
def tampered_file_fails(env):
    frame = env.encrypted(FILES[:2])
    flip_byte(os.path.join(env.work, "net.net.xml"), 100)
    expect_failed(*env.run(["--keyring-stdin", "-n", "net.net.xml", "-r", "routes.rou.xml"], frame),
                  "Could not decrypt")


@case()
def wrong_key_fails(env):
    frame = bytearray(env.encrypted(FILES[:2]))
    path_len = (frame[8] << 8) | frame[9]
    frame[10 + path_len] ^= 0x01
    expect_failed(*env.run(["--keyring-stdin", "-n", "net.net.xml", "-r", "routes.rou.xml"], bytes(frame)),
                  "Could not decrypt")


@case()
def invalid_frame_fails(env):
    frame = bytearray(env.encrypted(FILES[:2]))
    frame[0] = ord("X")
    code, out = env.run(["--keyring-stdin", "-n", "net.net.xml", "-r", "routes.rou.xml"], bytes(frame))
    expect(code == 1, "invalid frame should exit 1, got %s" % code)
    expect("invalid keyring" in out, "missing 'invalid keyring'")
    code, out = env.run(["--keyring-stdin", "-n", "net.net.xml", "-r", "routes.rou.xml"], b"DKR1\x00\x00\x01\x01")
    expect(code == 1 and "invalid keyring" in out, "more than 256 entries must be refused")


@case(hardened=True)
def hardened_refuses_plain_file(env):
    frame = env.encrypted(FILES[1:2])
    env.plain("net.net.xml")
    expect_failed(*env.run(["--keyring-stdin", "-n", "net.net.xml", "-r", "routes.rou.xml"], frame),
                  "has no key in the keyring")


@case(hardened=True)
def hardened_requires_keyring(env):
    env.plain("net.net.xml")
    code, out = env.run(["-n", "net.net.xml"])
    expect(code == 1, "hardened sumo without --keyring-stdin should exit 1, got %s" % code)
    expect("keyring required" in out, "missing 'keyring required'")


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def non_loopback_address():
    """A local IPv4 address that is not loopback; no packet is sent."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("192.0.2.1", 9))
            address = s.getsockname()[0]
        except OSError:
            return None
    return None if address.startswith("127.") or address == "0.0.0.0" else address


def listen_addresses(port):
    """Local addresses with a TCP listen socket on port, from the OS socket table."""
    if sys.platform == "darwin":
        # macOS netstat no longer lists every listen socket
        proc = subprocess.run(["lsof", "-nP", "-iTCP:%s" % port, "-sTCP:LISTEN", "-Fn"], stdout=subprocess.PIPE)
        hosts = [line[1:].rpartition(":")[0] for line in proc.stdout.decode(errors="replace").splitlines()
                 if line.startswith("n")]
        return sorted(set(hosts))
    if sys.platform == "win32":
        out, state, column, sep = subprocess.check_output(["netstat", "-an", "-p", "TCP"]), "LISTENING", 1, ":"
    else:
        out, state, column, sep = subprocess.check_output(["ss", "-ltnH"]), "LISTEN", 3, ":"
    result = []
    for line in out.decode(errors="replace").splitlines():
        fields = line.split()
        if len(fields) > column and state in fields:
            host, _, local_port = fields[column].rpartition(sep)
            if local_port == str(port):
                result.append(host)
    return sorted(set(result))


def try_connect(host, port, timeout=1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return s
    except OSError:
        s.close()
        return None


@case(hardened=True)
def hardened_refuses_output_options(env):
    frame = env.encrypted(FILES[:2])
    for option in (["--fcd-output", "out.xml"], ["--fcd-output.geo", "--fcd-output", "out.xml"],
                   ["--netstate-dump", "out.xml"], ["--ndump", "out.xml"], ["--full-output", "out.xml"],
                   ["--vtk-output", "out.xml"], ["--amitran-output", "out.xml"], ["--save-configuration", "out.xml"],
                   ["--write-license"], ["--tripinfo-output", "out.xml"], ["--save-state.times", "10"],
                   ["--device.ssm.probability", "1", "--device.ssm.file", "out.xml"]):
        expect_failed(*env.run(["--keyring-stdin", "-n", "net.net.xml", "-r", "routes.rou.xml"] + option, frame),
                      "in this hardened build")
        expect(not os.path.exists(os.path.join(env.work, "out.xml")), "%s wrote a file" % option)


@case(hardened=True)
def hardened_refuses_ssm_device(env):
    frame = env.encrypted(FILES[:2])
    for option in (["--device.ssm.probability", "1"], ["--device.ssm.deterministic"],
                   ["--device.ssm.explicit", "v0"], ["--num-clients", "2"], ["--verbose"]):
        expect_failed(*env.run(["--keyring-stdin", "-n", "net.net.xml", "-r", "routes.rou.xml"] + option, frame),
                      "in this hardened build")
        leftovers = [f for f in os.listdir(env.work) if f.startswith("ssm")]
        expect(not leftovers, "%s wrote %s" % (option, leftovers))


@case(hardened=True)
def hardened_refuses_option_from_config(env):
    with open(os.path.join(env.data, "run.sumocfg"), "rb") as f:
        config = f.read().replace(b"</configuration>",
                                  b"<processing><device.ssm.probability value=\"1\"/></processing></configuration>")
    src = tempfile.mkdtemp(prefix="sumo-keyring-cfg-")
    try:
        with open(os.path.join(src, "evil.sumocfg"), "wb") as f:
            f.write(config)
        saved, env.data = env.data, src
        for name in FILES[:3]:
            shutil.copy(os.path.join(saved, name), src)
        frame = env.encrypted(FILES[:3] + ["evil.sumocfg"])
        env.data = saved
    finally:
        shutil.rmtree(src)
    expect_failed(*env.run(["--keyring-stdin", "-c", "evil.sumocfg"], frame), "in this hardened build")
    leftovers = [f for f in os.listdir(env.work) if f.startswith("ssm")]
    expect(not leftovers, "wrote %s" % leftovers)


@case(hardened=True)
def hardened_accepts_darts_options(env):
    """Every option on the allowlist, as DARTS would pass them, driven over TraCI."""
    sys.path.insert(0, TOOLS)
    import traci
    port = free_port()
    frame = env.encrypted(FILES)
    args = ["--keyring-stdin", "-c", "run.sumocfg", "-n", "net.net.xml", "-r", "routes.rou.xml",
            "-a", "shapes.add.xml", "--remote-port", str(port), "--num-clients", "1", "--step-length", "0.5",
            "--begin", "0", "--seed", "42", "--random", "false", "--time-to-teleport", "-1", "--no-warnings",
            "--verbose", "false", "--duration-log.disable", "--collision.action", "warn",
            "--collision.check-junctions", "--default.speeddev", "0.1", "--ignore-route-errors",
            "--max-depart-delay", "60", "--log", "all.log", "--message-log", "message.log", "--error-log", "error.log"]
    proc = env.start(args, frame)
    try:
        traci.init(port=port, numRetries=100)
        expect(set(traci.edge.getIDList()) >= {"e0", "e1"}, "the net was not loaded")
        expect("p0" in traci.polygon.getIDList(), "the additional file was not loaded")
        departed = set()
        for _ in range(20):
            traci.simulationStep()
            departed.update(traci.simulation.getDepartedIDList())
        expect("v0" in departed, "the vehicle did not depart")
        traci.close()
    finally:
        code, out = env.finish(proc)
    expect(code == 0, "sumo exited with %s" % code)


@case()
def traci_bind_address(env):
    """Hardened: the TraCI port does not answer on a non-loopback address. Non-hardened: it does (shows the probe
    works)."""
    address = non_loopback_address()
    if address is None:
        print("skipped: no non-loopback IPv4 address")
        sys.exit(77)
    port = free_port()
    frame = env.encrypted(FILES[:2])
    proc = env.start(["--keyring-stdin", "-n", "net.net.xml", "-r", "routes.rou.xml", "--remote-port", str(port)],
                     frame)
    client = probe = None
    try:
        # hardened sumo takes one client only, so wait for the listen socket without connecting to it
        deadline = time.time() + 30
        addresses = []
        while not addresses and time.time() < deadline and proc.poll() is None:
            addresses = listen_addresses(port)
            if not addresses:
                time.sleep(0.1)
        print("listening on %s" % addresses)
        expect(addresses, "TraCI did not listen")
        if env.hardened:
            expect(addresses == ["127.0.0.1"], "hardened TraCI listens on %s" % addresses)
        probe = try_connect(address, port)
        if env.hardened:
            expect(probe is None, "hardened TraCI answered on %s" % address)
            deadline = time.time() + 30
            while client is None and time.time() < deadline and proc.poll() is None:
                client = try_connect("127.0.0.1", port)
                if client is None:
                    time.sleep(0.1)
            expect(client is not None, "TraCI did not listen on 127.0.0.1")
        else:
            expect(probe is not None, "TraCI did not answer on %s, the probe cannot tell" % address)
    finally:
        for s in (client, probe):
            if s is not None:
                s.close()
        env.finish(proc, kill=True)


@case(hardened=True)
def hardened_refuses_traci_load(env):
    sys.path.insert(0, TOOLS)
    import traci
    from traci.exceptions import TraCIException
    port = free_port()
    frame = env.encrypted(FILES[:2])
    proc = env.start(["--keyring-stdin", "-n", "net.net.xml", "-r", "routes.rou.xml", "--remote-port", str(port)],
                     frame)
    try:
        traci.init(port=port, numRetries=100)
        try:
            traci.load(["-n", "net.net.xml", "--fcd-output", "out.xml"])
            raise AssertionError("CMD_LOAD was accepted")
        except TraCIException as e:
            expect("disabled in this build" in str(e), "unexpected load error %s" % e)
        try:
            traci.simulation.saveState("state.xml")
            raise AssertionError("saveState was accepted")
        except TraCIException as e:
            expect("disabled in this build" in str(e), "unexpected saveState error %s" % e)
        traci.simulationStep()
        traci.close()
    finally:
        code, out = env.finish(proc)
    expect(code == 0, "sumo exited with %s" % code)
    expect(not os.path.exists(os.path.join(env.work, "out.xml")), "fcd output was written")
    expect(not os.path.exists(os.path.join(env.work, "state.xml")), "a state file was written")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sumo", required=True)
    parser.add_argument("--encrypt", required=True)
    parser.add_argument("--data", required=True)
    parser.add_argument("--hardened", default="OFF")
    parser.add_argument("case", choices=sorted(CASES))
    args = parser.parse_args()
    hardened = args.hardened.upper() in ("1", "ON", "TRUE", "YES")
    fn, needs = CASES[args.case]
    if needs is not None and needs != hardened:
        print("skipped: needs a %s build" % ("hardened" if needs else "non-hardened"))
        return 77
    env = Env(args)
    env.hardened = hardened
    try:
        fn(env)
    except AssertionError as e:
        print("FAIL: %s" % e)
        return 1
    finally:
        env.cleanup()
    print("PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
