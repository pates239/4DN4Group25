How to Run Telnet 

1: On the server machine: 

1.1 Find the server’s IP address

1.2 Start the server:
python3 Telnet_Server.py


2. On the same device or or another device in the same local network:

2.1 In Telnet_Client.py, replace “192.168.2.114” with the server’s IP address obtained from step 1.1.

2.2 Start the client:
python3 Telnet_Client.py

3. Client-server communications
Type messages from the client window and wait for the server to echo them.
Type exit to close the connection.
