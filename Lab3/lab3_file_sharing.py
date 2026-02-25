#!/usr/bin/env python3

import argparse
import os
import socket
import threading
from pathlib import Path
from typing import Optional


MSG_ENCODING = "utf-8"
RECV_SIZE = 4096

# Protocol field sizes.
CMD_FIELD_LEN = 1
STATUS_FIELD_LEN = 1
NAME_LEN_FIELD_LEN = 2
SIZE_FIELD_LEN = 8

DISCOVERY_MSG = "SERVICEDISCOVERY"
DISCOVERY_TIMEOUT = 1.5
DISCOVERY_CYCLES = 2


CMD = {
    "LIST": 1,
    "GET": 2,
    "PUT": 3,
    "BYE": 4,
}

STATUS = {
    "OK": 0,
    "ERR": 1,
}


def recv_exact(sock: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Socket closed while receiving data.")
        data.extend(chunk)
    return bytes(data)


def list_directory(directory: Path) -> list[str]:
    if not directory.exists():
        return []
    return sorted([p.name for p in directory.iterdir() if p.is_file()])


class FileSharingServer:
    def __init__(self, shared_dir: Path, sdp_port: int, fsp_port: int, service_name: str):
        self.shared_dir = shared_dir.resolve()
        self.shared_dir.mkdir(parents=True, exist_ok=True)
        self.sdp_port = sdp_port
        self.fsp_port = fsp_port
        self.service_name = service_name
        self.shutdown_event = threading.Event()

    def start(self) -> None:
        print(f"Shared directory: {self.shared_dir}")
        initial = list_directory(self.shared_dir)
        print("Initially available files:")
        if initial:
            for name in initial:
                print(f"  - {name}")
        else:
            print("  (none)")

        udp_thread = threading.Thread(target=self._run_discovery_listener, daemon=True)
        udp_thread.start()
        self._run_file_service_listener()

    def _run_discovery_listener(self) -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("", self.sdp_port))
                print(f"Listening for service discovery messages on SDP port {self.sdp_port}")

                while not self.shutdown_event.is_set():
                    try:
                        data, address = sock.recvfrom(RECV_SIZE)
                        msg = data.decode(MSG_ENCODING, errors="replace").strip()
                        if msg == DISCOVERY_MSG:
                            response = self.service_name.encode(MSG_ENCODING)
                            sock.sendto(response, address)
                    except OSError:
                        break
                    except Exception as exc:
                        print(f"Discovery listener error: {exc}")
        except Exception as exc:
            print(f"Could not start discovery listener on UDP {self.sdp_port}: {exc}")

    def _run_file_service_listener(self) -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listen_sock:
                listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listen_sock.bind(("", self.fsp_port))
                listen_sock.listen(20)
                print(f"Listening for file sharing connections on port {self.fsp_port}")

                try:
                    while True:
                        conn, addr = listen_sock.accept()
                        print(f"Connection received from {addr[0]} on port {addr[1]}")
                        t = threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True)
                        t.start()
                except KeyboardInterrupt:
                    print("\nShutting down server.")
                    self.shutdown_event.set()
        except Exception as exc:
            print(f"Could not start file service listener on TCP {self.fsp_port}: {exc}")
            self.shutdown_event.set()

    def _handle_client(self, conn: socket.socket, addr) -> None:
        with conn:
            while True:
                try:
                    cmd = recv_exact(conn, CMD_FIELD_LEN)[0]
                    if cmd == CMD["LIST"]:
                        self._handle_list(conn)
                    elif cmd == CMD["GET"]:
                        self._handle_get(conn)
                    elif cmd == CMD["PUT"]:
                        self._handle_put(conn)
                    elif cmd == CMD["BYE"]:
                        print(f"Connection closed by client {addr[0]}:{addr[1]}")
                        break
                    else:
                        print(f"Unknown command from {addr[0]}:{addr[1]}: {cmd}")
                        break
                except ConnectionError:
                    print(f"Connection dropped: {addr[0]}:{addr[1]}")
                    break
                except Exception as exc:
                    print(f"Client handler error for {addr[0]}:{addr[1]}: {exc}")
                    break

    def _recv_name(self, conn: socket.socket) -> str:
        name_len = int.from_bytes(recv_exact(conn, NAME_LEN_FIELD_LEN), byteorder="big")
        name_bytes = recv_exact(conn, name_len)
        return name_bytes.decode(MSG_ENCODING, errors="strict")

    def _send_status_and_payload(self, conn: socket.socket, status_code: int, payload: bytes) -> None:
        pkt = (
            status_code.to_bytes(STATUS_FIELD_LEN, byteorder="big")
            + len(payload).to_bytes(SIZE_FIELD_LEN, byteorder="big")
            + payload
        )
        conn.sendall(pkt)

    def _handle_list(self, conn: socket.socket) -> None:
        entries = list_directory(self.shared_dir)
        payload = "\n".join(entries).encode(MSG_ENCODING)
        self._send_status_and_payload(conn, STATUS["OK"], payload)

    def _handle_get(self, conn: socket.socket) -> None:
        name = self._recv_name(conn)
        path = self.shared_dir / name
        if not path.exists() or not path.is_file():
            self._send_status_and_payload(conn, STATUS["ERR"], b"File not found.")
            return

        data = path.read_bytes()
        self._send_status_and_payload(conn, STATUS["OK"], data)
        print(f"Sent file: {name} ({len(data)} bytes)")

    def _handle_put(self, conn: socket.socket) -> None:
        name = self._recv_name(conn)
        size = int.from_bytes(recv_exact(conn, SIZE_FIELD_LEN), byteorder="big")
        final_path = self.shared_dir / name

        received = 0

        try:
            with open(final_path, "wb") as tf:
                while received < size:
                    chunk = conn.recv(min(RECV_SIZE, size - received))
                    if not chunk:
                        raise ConnectionError("Upload interrupted.")
                    tf.write(chunk)
                    received += len(chunk)

            msg = f"Stored {name} ({received} bytes)"
            self._send_status_and_payload(conn, STATUS["OK"], msg.encode(MSG_ENCODING))
            print(msg)
        except Exception as exc:
            err = f"Upload failed for {name}: {exc}"
            print(err)
            try:
                self._send_status_and_payload(conn, STATUS["ERR"], err.encode(MSG_ENCODING))
            except Exception:
                pass


class FileSharingClient:
    def __init__(self, local_dir: Path, sdp_port: int):
        self.local_dir = local_dir.resolve()
        self.local_dir.mkdir(parents=True, exist_ok=True)
        self.sdp_port = sdp_port
        self.conn: Optional[socket.socket] = None
        self.connected_to: Optional[tuple[str, int]] = None

    def run(self) -> None:
        print(f"Local sharing directory: {self.local_dir}")
        print("Commands: scan | connect <ip> <port> | llist | rlist | put <filename> | get <filename> | bye | quit")
        while True:
            try:
                raw = input("client> ").strip()
            except EOFError:
                raw = "quit"

            if not raw:
                continue

            parts = raw.split()
            cmd = parts[0].lower()

            if cmd == "scan":
                self.scan()
            elif cmd == "connect" and len(parts) == 3:
                self.connect(parts[1], int(parts[2]))
            elif cmd == "llist":
                self.local_list()
            elif cmd == "rlist":
                self.remote_list()
            elif cmd == "put" and len(parts) == 2:
                self.put(parts[1])
            elif cmd == "get" and len(parts) == 2:
                self.get(parts[1])
            elif cmd == "bye":
                self.bye()
            elif cmd == "quit":
                self.bye()
                break
            else:
                print("Invalid command.")

    def _require_connection(self) -> bool:
        if self.conn is None:
            print("Not connected. Use: connect <ip> <port>")
            return False
        return True

    def _send_name(self, name: str) -> bytes:
        name_bytes = name.encode(MSG_ENCODING)
        return len(name_bytes).to_bytes(NAME_LEN_FIELD_LEN, byteorder="big") + name_bytes

    def _recv_status_and_payload(self) -> tuple[int, bytes]:
        status = recv_exact(self.conn, STATUS_FIELD_LEN)[0]
        size = int.from_bytes(recv_exact(self.conn, SIZE_FIELD_LEN), byteorder="big")
        payload = recv_exact(self.conn, size) if size > 0 else b""
        return status, payload

    def scan(self) -> None:
        results = []
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(DISCOVERY_TIMEOUT)

            for i in range(DISCOVERY_CYCLES):
                try:
                    sock.sendto(DISCOVERY_MSG.encode(MSG_ENCODING), ("255.255.255.255", self.sdp_port))
                except Exception as exc:
                    print(f"Discovery broadcast failed: {exc}")
                    return
                print(f"Sent discovery broadcast {i + 1}/{DISCOVERY_CYCLES}")
                while True:
                    try:
                        data, addr = sock.recvfrom(RECV_SIZE)
                        service = data.decode(MSG_ENCODING, errors="replace")
                        entry = (service, addr[0], addr[1])
                        if entry not in results:
                            results.append(entry)
                    except socket.timeout:
                        break

        if results:
            for service, ip, port in results:
                print(f"{service} found at {ip}:{port}")
        else:
            print("No service found.")

    def connect(self, ip: str, port: int) -> None:
        self.bye()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((ip, port))
            self.conn = sock
            self.connected_to = (ip, port)
            print(f"Connected to {ip}:{port}")
        except Exception as exc:
            print(f"Connect failed: {exc}")

    def local_list(self) -> None:
        entries = list_directory(self.local_dir)
        if entries:
            for name in entries:
                print(name)
        else:
            print("(no local files)")

    def remote_list(self) -> None:
        if not self._require_connection():
            return

        try:
            self.conn.sendall(CMD["LIST"].to_bytes(CMD_FIELD_LEN, byteorder="big"))
            status, payload = self._recv_status_and_payload()
            if status != STATUS["OK"]:
                print(payload.decode(MSG_ENCODING, errors="replace"))
                return
            text = payload.decode(MSG_ENCODING, errors="replace")
            if text.strip():
                print(text)
            else:
                print("(no remote files)")
        except Exception as exc:
            print(f"rlist failed: {exc}")
            self.bye()

    def put(self, filename: str) -> None:
        if not self._require_connection():
            return

        path = self.local_dir / filename
        if not path.exists() or not path.is_file():
            print(f"Local file not found: {filename}")
            return

        data = path.read_bytes()
        pkt = (
            CMD["PUT"].to_bytes(CMD_FIELD_LEN, byteorder="big")
            + self._send_name(filename)
            + len(data).to_bytes(SIZE_FIELD_LEN, byteorder="big")
            + data
        )

        try:
            self.conn.sendall(pkt)
            status, payload = self._recv_status_and_payload()
            msg = payload.decode(MSG_ENCODING, errors="replace")
            if status == STATUS["OK"]:
                print(f"Upload success: {msg}")
            else:
                print(f"Upload error: {msg}")
        except Exception as exc:
            print(f"put failed: {exc}")
            self.bye()

    def get(self, filename: str) -> None:
        if not self._require_connection():
            return

        pkt = CMD["GET"].to_bytes(CMD_FIELD_LEN, byteorder="big") + self._send_name(filename)
        try:
            self.conn.sendall(pkt)
            status, payload = self._recv_status_and_payload()
            if status != STATUS["OK"]:
                print(f"Get failed: {payload.decode(MSG_ENCODING, errors='replace')}")
                return
            out = self.local_dir / filename
            out.write_bytes(payload)
            print(f"Downloaded {filename} ({len(payload)} bytes)")
        except Exception as exc:
            print(f"get failed: {exc}")
            self.bye()

    def bye(self) -> None:
        if self.conn is None:
            return
        try:
            self.conn.sendall(CMD["BYE"].to_bytes(CMD_FIELD_LEN, byteorder="big"))
        except Exception:
            pass
        try:
            self.conn.close()
        except Exception:
            pass
        if self.connected_to:
            print(f"Disconnected from {self.connected_to[0]}:{self.connected_to[1]}")
        self.conn = None
        self.connected_to = None


def parse_args():
    parser = argparse.ArgumentParser(description="4DN4 Lab 3 file sharing client/server.")
    sub = parser.add_subparsers(dest="role", required=True)

    srv = sub.add_parser("server", help="Run file sharing server")
    srv.add_argument("--shared-dir", required=True, help="Path to server shared directory")
    srv.add_argument("--sdp-port", type=int, default=30000, help="Service discovery UDP port")
    srv.add_argument("--fsp-port", type=int, default=30001, help="File sharing TCP port")
    srv.add_argument("--service-name", default="Team File Sharing Service", help="Advertised service name")

    cli = sub.add_parser("client", help="Run file sharing client")
    cli.add_argument("--local-dir", required=True, help="Path to client local sharing directory")
    cli.add_argument("--sdp-port", type=int, default=30000, help="Service discovery UDP port")

    return parser.parse_args()


def main():
    args = parse_args()
    if args.role == "server":
        server = FileSharingServer(
            shared_dir=Path(args.shared_dir),
            sdp_port=args.sdp_port,
            fsp_port=args.fsp_port,
            service_name=args.service_name,
        )
        server.start()
    else:
        client = FileSharingClient(local_dir=Path(args.local_dir), sdp_port=args.sdp_port)
        client.run()


if __name__ == "__main__":
    main()
