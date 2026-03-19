#!/usr/bin/env python3

import argparse
import ipaddress
import json
import shlex
import socket
import struct
import threading
from dataclasses import dataclass
from typing import Optional


MSG_ENCODING = "utf-8"
RECV_SIZE = 4096
DEFAULT_SERVER_HOST = "127.0.0.1"
DEFAULT_CRDP_PORT = 32000
CHAT_EXIT_SEQUENCE = "\x1d"


def recv_until_newline(sock: socket.socket) -> Optional[str]:
    data = bytearray()
    while True:
        chunk = sock.recv(1)
        if not chunk:
            return None if not data else data.decode(MSG_ENCODING, errors="replace")
        if chunk == b"\n":
            return data.decode(MSG_ENCODING, errors="replace")
        data.extend(chunk)


def send_line(sock: socket.socket, text: str) -> None:
    sock.sendall((text + "\n").encode(MSG_ENCODING))


@dataclass
class ChatRoom:
    name: str
    address: str
    port: int


class ChatRoomDirectoryServer:
    def __init__(self, host: str, crdp_port: int):
        self.host = host
        self.crdp_port = crdp_port
        self.rooms: dict[str, ChatRoom] = {}
        self.rooms_lock = threading.Lock()
        self.shutdown_event = threading.Event()

    def start(self) -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listen_sock:
                listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listen_sock.bind((self.host, self.crdp_port))
                listen_sock.listen(20)
                print(f"Chat Room Directory Server listening on port {self.crdp_port}...")

                try:
                    while True:
                        conn, addr = listen_sock.accept()
                        print(f"Client connected from {addr[0]}:{addr[1]}")
                        threading.Thread(
                            target=self._handle_client,
                            args=(conn, addr),
                            daemon=True,
                        ).start()
                except KeyboardInterrupt:
                    print("\nShutting down Chat Room Directory Server.")
                    self.shutdown_event.set()
        except Exception as exc:
            print(f"Could not start CRDS on port {self.crdp_port}: {exc}")

    def _handle_client(self, conn: socket.socket, addr) -> None:
        with conn:
            while True:
                try:
                    line = recv_until_newline(conn)
                    if line is None:
                        break
                    response, should_close = self._process_command(line.strip())
                    send_line(conn, response)
                    if should_close:
                        break
                except ConnectionError:
                    break
                except Exception as exc:
                    send_line(conn, f"ERR Server error: {exc}")
                    break

        print(f"Connection closed for {addr[0]}:{addr[1]}")

    def _process_command(self, line: str) -> tuple[str, bool]:
        if not line:
            return "ERR Empty command.", False

        try:
            parts = shlex.split(line)
        except ValueError as exc:
            return f"ERR {exc}", False

        cmd = parts[0].lower()

        if cmd == "getdir":
            return self._cmd_getdir(), False
        if cmd == "makeroom":
            if len(parts) != 4:
                return "ERR Usage: makeroom <chat room name> <address> <port>", False
            room_name, address, port_text = parts[1], parts[2], parts[3]
            return self._cmd_makeroom(room_name, address, port_text), False
        if cmd == "deleteroom":
            if len(parts) != 2:
                return "ERR Usage: deleteroom <chat room name>", False
            return self._cmd_deleteroom(parts[1]), False
        if cmd == "bye":
            return "OK Goodbye.", True

        return "ERR Unknown command.", False

    def _cmd_getdir(self) -> str:
        with self.rooms_lock:
            rooms = sorted(self.rooms.values(), key=lambda room: room.name)

        if not rooms:
            return "OKDIR []"

        payload = [
            {"name": room.name, "address": room.address, "port": room.port}
            for room in rooms
        ]
        return "OKDIR " + json.dumps(payload)

    def _cmd_makeroom(self, room_name: str, address: str, port_text: str) -> str:
        if not room_name:
            return "ERR Chat room name cannot be empty."

        try:
            multicast_ip = ipaddress.ip_address(address)
        except ValueError:
            return "ERR Invalid IP address."

        if not multicast_ip.is_multicast or not str(multicast_ip).startswith("239."):
            return "ERR Address must be in the administratively scoped multicast range 239.0.0.0/8."

        try:
            port = int(port_text)
        except ValueError:
            return "ERR Port must be an integer."

        if not (1024 <= port <= 65535):
            return "ERR Port must be between 1024 and 65535."

        with self.rooms_lock:
            if room_name in self.rooms:
                return "ERR Chat room name already exists."

            for room in self.rooms.values():
                if room.address == address and room.port == port:
                    return "ERR Address/port combination must be unique."

            self.rooms[room_name] = ChatRoom(name=room_name, address=address, port=port)

        return f"OK Created room {room_name} {address} {port}"

    def _cmd_deleteroom(self, room_name: str) -> str:
        with self.rooms_lock:
            room = self.rooms.pop(room_name, None)

        if room is None:
            return "ERR Chat room not found."
        return f"OK Deleted room {room_name}"


class MulticastChatSession:
    def __init__(self, chat_name: str, room: ChatRoom):
        self.chat_name = chat_name
        self.room = room
        self.stop_event = threading.Event()
        self.recv_sock: Optional[socket.socket] = None
        self.send_sock: Optional[socket.socket] = None

    def start(self) -> None:
        self.recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.recv_sock.bind(("", self.room.port))
        except OSError:
            self.recv_sock.bind((self.room.address, self.room.port))

        mreq = struct.pack("4s4s", socket.inet_aton(self.room.address), socket.inet_aton("0.0.0.0"))
        self.recv_sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        self.send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)

        receiver = threading.Thread(target=self._receive_loop, daemon=True)
        receiver.start()

        print(f"Entered chat mode for room '{self.room.name}'.")
        print("Type messages and press Enter to send.")
        print("Press Ctrl+] then Enter to exit chat mode.")

        try:
            while True:
                line = input(f"{self.room.name}> ")
                if line == CHAT_EXIT_SEQUENCE:
                    break
                if not line.strip():
                    continue
                message = f"{self.chat_name}: {line}"
                self.send_sock.sendto(message.encode(MSG_ENCODING), (self.room.address, self.room.port))
        finally:
            self.stop_event.set()
            if self.recv_sock is not None:
                try:
                    self.recv_sock.close()
                except Exception:
                    pass
            if self.send_sock is not None:
                try:
                    self.send_sock.close()
                except Exception:
                    pass
            print(f"Exited chat mode for room '{self.room.name}'.")

    def _receive_loop(self) -> None:
        while not self.stop_event.is_set():
            try:
                data, _ = self.recv_sock.recvfrom(RECV_SIZE)
                text = data.decode(MSG_ENCODING, errors="replace")
                print(f"\n{text}")
            except OSError:
                break
            except Exception as exc:
                if not self.stop_event.is_set():
                    print(f"\nChat receive error: {exc}")
                break


class ChatClient:
    def __init__(self, server_host: str, crdp_port: int):
        self.server_host = server_host
        self.crdp_port = crdp_port
        self.crds_sock: Optional[socket.socket] = None
        self.chat_name = "Anonymous"

    def run(self) -> None:
        print(f"Client ready. Default chat name: {self.chat_name}")
        print("Main commands: connect | name <chat name> | chat <chat room name> | quit")

        while True:
            prompt = "crds> " if self.crds_sock else "client> "
            try:
                raw = input(prompt).strip()
            except EOFError:
                raw = "quit"

            if not raw:
                continue

            parts = raw.split()
            cmd = parts[0].lower()

            if self.crds_sock is None:
                if cmd == "connect":
                    self.connect()
                elif cmd == "name":
                    try:
                        name_parts = shlex.split(raw)
                    except ValueError as exc:
                        print(f"Invalid name command: {exc}")
                        continue
                    if len(name_parts) < 2:
                        print("Usage: name <chat name>")
                        continue
                    self.chat_name = " ".join(name_parts[1:])
                    print(f"Chat name set to {self.chat_name}")
                elif cmd == "chat":
                    try:
                        chat_parts = shlex.split(raw)
                    except ValueError as exc:
                        print(f"Invalid chat command: {exc}")
                        continue
                    if len(chat_parts) != 2:
                        print("Usage: chat <chat room name>")
                        continue
                    self.chat(chat_parts[1])
                elif cmd == "quit":
                    break
                else:
                    print("Available main commands: connect | name <chat name> | chat <chat room name> | quit")
            else:
                if cmd in {"getdir", "makeroom", "deleteroom", "bye"}:
                    self._send_crds_command(raw)
                elif cmd == "quit":
                    self.disconnect_from_crds()
                    break
                else:
                    print("Available CRDS commands: getdir | makeroom <name> <address> <port> | deleteroom <name> | bye")

        self.disconnect_from_crds()

    def connect(self) -> None:
        if self.crds_sock is not None:
            print("Already connected to the CRDS.")
            return

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.server_host, self.crdp_port))
            self.crds_sock = sock
            print(f"Connected to CRDS at {self.server_host}:{self.crdp_port}")
            print("CRDS commands: getdir | makeroom <name> <address> <port> | deleteroom <name> | bye")
        except Exception as exc:
            print(f"Connect failed: {exc}")

    def disconnect_from_crds(self) -> None:
        if self.crds_sock is None:
            return
        try:
            self.crds_sock.close()
        except Exception:
            pass
        self.crds_sock = None

    def _send_crds_command(self, command: str) -> None:
        if self.crds_sock is None:
            print("Not connected to the CRDS.")
            return

        try:
            send_line(self.crds_sock, command)
            response = recv_until_newline(self.crds_sock)
            if response is None:
                print("CRDS connection closed.")
                self.disconnect_from_crds()
                return

            if command.strip().lower() == "getdir":
                self._print_directory_response(response)
            else:
                print(response)
            if command.strip().lower() == "bye":
                self.disconnect_from_crds()
        except Exception as exc:
            print(f"CRDS command failed: {exc}")
            self.disconnect_from_crds()

    def _print_directory_response(self, response: str) -> None:
        if not response.startswith("OKDIR "):
            print(response)
            return

        try:
            rooms = json.loads(response[6:].strip())
        except json.JSONDecodeError:
            print(response)
            return

        if not rooms:
            print("OK No chat rooms.")
            return

        print("OK Chat room directory:")
        for room in rooms:
            print(f"  {room['name']} {room['address']} {room['port']}")

    def _fetch_directory(self) -> dict[str, ChatRoom]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((self.server_host, self.crdp_port))
            send_line(sock, "getdir")
            response = recv_until_newline(sock)
            if response is None:
                raise ConnectionError("No response from CRDS.")
        finally:
            sock.close()

        if not response.startswith("OKDIR "):
            raise RuntimeError(response)

        payload = response[6:].strip()
        room_entries = json.loads(payload)
        rooms = {}
        for entry in room_entries:
            rooms[entry["name"]] = ChatRoom(
                name=entry["name"],
                address=entry["address"],
                port=int(entry["port"]),
            )
        return rooms

    def chat(self, room_name: str) -> None:
        try:
            rooms = self._fetch_directory()
        except Exception as exc:
            print(f"Could not fetch chat room directory: {exc}")
            return

        room = rooms.get(room_name)
        if room is None:
            print(f"Chat room not found: {room_name}")
            return

        try:
            session = MulticastChatSession(self.chat_name, room)
            session.start()
        except KeyboardInterrupt:
            print()
        except Exception as exc:
            print(f"Could not start chat mode: {exc}")


def parse_args():
    parser = argparse.ArgumentParser(description="4DN4 Lab 4 online group chatting application.")
    sub = parser.add_subparsers(dest="role", required=True)

    srv = sub.add_parser("server", help="Run the Chat Room Directory Server")
    srv.add_argument("--host", default="", help="Interface/host to bind the CRDS to")
    srv.add_argument("--crdp-port", type=int, default=DEFAULT_CRDP_PORT, help="Chat Room Directory Port")

    cli = sub.add_parser("client", help="Run the chat client")
    cli.add_argument("--server-host", default=DEFAULT_SERVER_HOST, help="CRDS host name or IP address")
    cli.add_argument("--crdp-port", type=int, default=DEFAULT_CRDP_PORT, help="Chat Room Directory Port")

    return parser.parse_args()


def main():
    args = parse_args()
    if args.role == "server":
        server = ChatRoomDirectoryServer(host=args.host, crdp_port=args.crdp_port)
        server.start()
    else:
        client = ChatClient(server_host=args.server_host, crdp_port=args.crdp_port)
        client.run()


if __name__ == "__main__":
    main()
