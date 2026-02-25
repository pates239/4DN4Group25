# Lab 3 File Sharing - Quick Run Guide

## Requirements
- Python 3
- Run all commands from:
  `/4DN4Group25/Lab3`

## 1. Start the Server
Open Terminal 1:

```bash
python3 lab3_file_sharing.py server \
  --shared-dir ./server_share \
  --sdp-port 30000 \
  --fsp-port 30001 \
  --service-name "Shray Team File Sharing Service"
```

## 2. Start a Client
Open Terminal 2:

```bash
python3 lab3_file_sharing.py client --local-dir ./client1_share --sdp-port 30000
```

## 3. Client Commands
At the `client>` prompt, use:

- `scan` - discover services over UDP broadcast
- `connect <ip> <port>` - connect to server TCP socket
- `llist` - list local shared files
- `rlist` - list remote server shared files
- `put <filename>` - upload local file to server
- `get <filename>` - download file from server
- `bye` - close current server connection
- `quit` - exit client

## 4. Quick Test Flow
In client:

```text
scan
connect 127.0.0.1 30001
llist
rlist
put utf8_multibyte_test.txt
rlist
get utf8_multibyte_test.txt
llist
bye
quit
```

## 5. Optional: Concurrency Test
Open a second client terminal:

```bash
python3 lab3_file_sharing.py client --local-dir ./client2_share --sdp-port 30000
```

Connect both clients and run uploads/downloads to show concurrent handling.

## Notes
- The server and client can run on the same machine using `127.0.0.1`.
- Stop server with `Ctrl+C`.
