#!/usr/bin/env python3
"""Loopback interoperability and on-wire checks; no root or third-party modules."""
import argparse
import json
import os
from pathlib import Path
import secrets
import select
import socket
import subprocess
import tempfile
import threading
import time


class Proxy:
    def __init__(self, target_port, tamper=False, fragment=False):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.listener.settimeout(0.1)
        self.port = self.listener.getsockname()[1]
        self.target_port = target_port
        self.tamper = tamper
        self.fragment = fragment
        self.captured = []
        self.connections = []
        self.udp_captured = {}
        self.udp_listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_listener.bind(("127.0.0.1", self.port))
        self.workers = []
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()
        self.udp_thread = threading.Thread(target=self.forward_udp, daemon=True)
        self.udp_thread.start()

    def forward_udp(self):
        streams = {}
        sockets = {self.udp_listener: None}
        try:
            while not self.stopped.is_set():
                ready, _, _ = select.select(list(sockets), [], [], 0.1)
                for source in ready:
                    data, address = source.recvfrom(65536)
                    if source is self.udp_listener:
                        if address not in streams:
                            destination = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            destination.connect(("127.0.0.1", self.target_port))
                            streams[address] = destination
                            sockets[destination] = address
                            self.udp_captured[address] = [[], []]
                        if len(self.udp_captured[address][0]) < 4:
                            self.udp_captured[address][0].append(data)
                        streams[address].send(data)
                    else:
                        client = sockets[source]
                        if len(self.udp_captured[client][1]) < 4:
                            self.udp_captured[client][1].append(data)
                        self.udp_listener.sendto(data, client)
        except OSError:
            pass
        finally:
            for connection in streams.values():
                connection.close()

    def accept(self):
        while not self.stopped.is_set():
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            server = socket.create_connection(("127.0.0.1", self.target_port))
            index = len(self.captured)
            self.captured.append([bytearray(), bytearray()])
            self.connections.extend([client, server])
            for direction, source, destination in [(0, client, server), (1, server, client)]:
                worker = threading.Thread(
                    target=self.forward, args=(index, direction, source, destination), daemon=True
                )
                self.workers.append(worker)
                worker.start()

    def forward(self, index, direction, source, destination):
        first = True
        try:
            while data := source.recv(65536):
                capture = self.captured[index][direction]
                limit = 1024 * 1024 if index == 0 else 512
                capture.extend(data[:max(0, limit - len(capture))])
                if self.tamper and index == 0 and direction == 0 and first:
                    data = bytes([data[0] ^ 1]) + data[1:]
                first = False
                if self.fragment and index == 0:
                    for offset in range(0, len(data), 3):
                        destination.sendall(data[offset:offset + 3])
                else:
                    destination.sendall(data)
        except OSError:
            pass
        finally:
            try:
                destination.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def close(self):
        self.stopped.set()
        self.listener.close()
        self.udp_listener.close()
        for connection in self.connections:
            connection.close()
        self.thread.join(timeout=2)
        self.udp_thread.join(timeout=2)
        for worker in self.workers:
            worker.join(timeout=2)


def run_test(binary, env, options=(), proxy=False, tamper=False, fragment=False,
             server_env=None, server_binary=None, server_options=()):
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    server = subprocess.Popen(
        [server_binary or binary, "-s", "-1", "-B", "127.0.0.1", "-p", str(port), "--forceflush", *server_options],
        env=server_env if server_env is not None else env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    relay = None
    try:
        # Wait for the actual listening message; do not probe and consume -1's connection.
        import selectors
        selector = selectors.DefaultSelector()
        selector.register(server.stdout, selectors.EVENT_READ)
        startup = bytearray()
        deadline = time.monotonic() + 5
        while b"Server listening" not in startup:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise AssertionError(f"server did not start: {startup!r}")
            chunk = os.read(server.stdout.fileno(), 4096)
            if not chunk:
                raise AssertionError(f"server exited before listening: {startup!r}")
            startup.extend(chunk)
        selector.close()
        if proxy:
            relay = Proxy(port, tamper=tamper, fragment=fragment)
        result = subprocess.run(
            [binary, "-c", "127.0.0.1", "-p", str(relay.port if relay else port),
             "-t", "1", "-b", "10M", "--json", *options],
            env=env, capture_output=True, text=True, timeout=12,
        )
        if tamper or (server_env is not None and server_env != env):
            assert result.returncode != 0, "invalid authentication unexpectedly succeeded"
            return None, []
        assert result.returncode == 0, result.stdout + result.stderr
        output = json.loads(result.stdout)
        assert "error" not in output, output
        assert output["end"]["streams"], "no measured data streams"
        assert any(item["sender"]["bytes"] > 0 if "sender" in item
                   else item["udp"]["bytes"] > 0 for item in output["end"]["streams"])
        assert output["end"].get("sum_received", output["end"].get("sum", {})).get("bytes", 0) > 0
        captured = relay.captured if relay else []
        if relay:
            for worker in relay.workers:
                worker.join(timeout=2)
            if "-u" in options and "--wire-plain" not in options:
                assert relay.udp_captured, "no captured UDP handshakes"
                for directions in relay.udp_captured.values():
                    assert len(directions[0][0]) == 32, "UDP connect is not wrapped"
                    assert any(len(packet) == 32 for packet in directions[1]), "UDP reply is not wrapped"
                    assert all(packet not in (b"6789", b"9876")
                               for direction in directions for packet in direction)
        server_output, _ = server.communicate(timeout=5)
        assert server.returncode == 0, server_output
        return output, captured
    finally:
        if relay:
            relay.close()
        if server.poll() is None:
            server.kill()
        server.communicate()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", nargs="?", default="src/iperf3")
    parser.add_argument("--wire-only", action="store_true")
    parser.add_argument("--stock-binary", help="also test plain-mode interoperability with an official iperf3")
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    plain = os.environ.copy()
    plain.pop("IPERF3_WIRE_KEY_FILE", None)
    with tempfile.TemporaryDirectory() as temp:
        config = Path(temp) / "config"
        key = config / "iperf3-lab" / "wire.key"
        key.parent.mkdir(parents=True)
        key.write_text(secrets.token_hex(32) + "\n")
        key.chmod(0o600)
        wire = dict(plain, XDG_CONFIG_HOME=str(config))
        first_cookies = []
        for options, fragment in [((), False), (("-R", "-P", "3"), True), (("--bidir",), False)]:
            output, captures = run_test(binary, wire, options, proxy=True, fragment=fragment)
            assert captures, "no captured connections"
            cookie = output["start"]["cookie"].encode()
            for connection in captures:
                for payload in connection:
                    for marker in (b'"client_version"', b'"parallel"', b'"cpu_util_total"', cookie):
                        assert marker not in payload, f"cleartext fingerprint leaked: {marker!r}"
            first_cookies.append(bytes(captures[0][0][:65]))
            assert len(captures[0][0]) >= 65
            assert len(captures[0][1]) >= 29
            # The same test cookie must have different ciphertext on each socket.
            assert len({bytes(connection[0][:65]) for connection in captures}) == len(captures)
            print(f"PASS encrypted TCP {options}, fragmentation={fragment}", flush=True)
        assert len(set(first_cookies)) == len(first_cookies), "handshake repeats between tests"
        if args.wire_only:
            return
        for options in [("-u", "-b", "1M"), ("-u", "-b", "1M", "-R", "-P", "2"),
                        ("-u", "-b", "1M", "--bidir")]:
            run_test(binary, wire, options, proxy=True)
            print(f"PASS encrypted UDP {options}", flush=True)
        for options in [(), ("-R",), ("-u", "-b", "1M")]:
            _, captures = run_test(binary, plain, (*options, "--wire-plain"),
                                   proxy="-u" not in options, server_options=("--wire-plain",))
            if captures:
                assert b'"client_version"' in captures[0][0], "plain mode is no longer compatible"
            print(f"PASS original mode {options}", flush=True)
        if args.stock_binary:
            stock = str(Path(args.stock_binary).resolve())
            run_test(binary, plain, ("--wire-plain",), server_binary=stock)
            run_test(stock, plain, server_binary=binary, server_options=("--wire-plain",))
            print("PASS official iperf3 interoperability in both roles", flush=True)
        run_test(binary, wire, proxy=True, tamper=True)
        print("PASS tampered ciphertext rejected", flush=True)
        other_config = Path(temp) / "other-config"
        other = other_config / "iperf3-lab" / "wire.key"
        other.parent.mkdir(parents=True)
        other.write_text(secrets.token_hex(32) + "\n")
        other.chmod(0o600)
        run_test(binary, wire, server_env=dict(plain, XDG_CONFIG_HOME=str(other_config)))
        print("PASS wrong key rejected", flush=True)
        missing = dict(plain, XDG_CONFIG_HOME=str(Path(temp) / "missing-config"))
        run_test(binary, missing, ("--wire-key-file", str(key)),
                 server_options=("--wire-key-file", str(key)))
        print("PASS explicit key file without environment variable", flush=True)
        for contents in ["bad\n", "0" * 63 + "g\n", "00" * 32 + "junk"]:
            key.write_text(contents)
            result = subprocess.run([binary, "-s", "-1"], env=wire, capture_output=True, timeout=2)
            assert result.returncode != 0, "invalid key was accepted"
        print("PASS malformed keys rejected", flush=True)
        result = subprocess.run([binary, "-s", "-1"], env=missing,
                                capture_output=True, timeout=2)
        assert result.returncode != 0
        print("PASS missing key rejected", flush=True)


if __name__ == "__main__":
    main()
