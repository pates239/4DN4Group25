import socket
import threading

HOST = '0.0.0.0'   # Listen on all interfaces
PORT = 8023        # Telnet uses 23 by default, but use 8023 to avoid permissions

def handle_client(conn, addr):
    print(f"[+] Connection from {addr}")
    conn.sendall(b"Welcome to the simple Telnet server!\r\nType 'exit' to disconnect.\r\n> ")
    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            message = data.decode(errors='ignore').strip()
            print(f"[{addr}] {message}")
            if message.lower() == 'exit':
                conn.sendall(b"Goodbye!\r\n")
                break
            response = f"You said: {message}\r\n> "
            conn.sendall(response.encode())
    finally:
        print(f"[-] Disconnected {addr}")
        conn.close()

def main():
    print(f"[+] Starting Telnet server on port {PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        while True:
            conn, addr = s.accept()
            thread = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            thread.start()

if __name__ == "__main__":
    main()

