# Lab 4 Online Group Chatting - Quick Run Guide

## Requirements
- Python 3
- Run all commands from:
  `/4DN4Group25/Lab4`

## 1. Start the Chat Room Directory Server
Open Terminal 1:

```bash
python3 lab4_group_chat.py server --crdp-port 32000
```

Expected output:

```text
Chat Room Directory Server listening on port 32000...
```

## 2. Start a Client
Open Terminal 2:

```bash
python3 lab4_group_chat.py client --server-host 127.0.0.1 --crdp-port 32000
```

## 3. Start a Second Client
Open Terminal 3:

```bash
python3 lab4_group_chat.py client --server-host 127.0.0.1 --crdp-port 32000
```

## 4. Main Client Commands
At the `client>` prompt, use:

- `connect`
- `name <chat name>`
- `chat <chat room name>`
- `quit`

## 5. CRDS Commands
After `connect`, the prompt changes to `crds>`.

Use:

- `getdir`
- `makeroom <chat room name> <multicast address> <port>`
- `deleteroom <chat room name>`
- `bye`

Use multicast addresses in the administratively scoped range `239.0.0.0` to `239.255.255.255`.

## 6. Demonstration Flow
Client 1:

```text
connect
makeroom room1 239.1.1.1 50001
getdir
bye
name alice
chat room1
```

Client 2:

```text
connect
getdir
bye
name bob
chat room1
```

Inside chat mode:

- type a message and press Enter to send it
- press `Ctrl+]` then Enter to leave chat mode

## Notes
- The server handles multiple CRDS clients concurrently with threads.
- Chat messages are exchanged directly with IP multicast, not through the CRDS.
- Chat room names are expected to be single words in this implementation.
