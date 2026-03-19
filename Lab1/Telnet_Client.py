import socket

HOST = '192.168.5.35'  # Replace with the server's local IP address
PORT = 8023

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print(f"Connected to {HOST}:{PORT}\n")
        while True:
            data = s.recv(1024)
            if not data:
                break
            print(data.decode(errors='ignore'), end='')
            msg = input()
            s.sendall((msg + '\r\n').encode())
            if msg.lower() == 'exit':
                break

if __name__ == "__main__":
    main()

