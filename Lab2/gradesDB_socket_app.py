#!/usr/bin/python3

"""
Lab 2 Server and Client Socket Application for Grade lookup 

By: Group 25 (Shray Patel, Siddh Patel, Umar Javaid)

to create a Client: "python EchoClientServer.py -r client" 
to create a Server: "python EchoClientServer.py -r server" 

or you can import the module into another file, e.g., 
import EchoClientServer

"""

########################################################################

import socket
import argparse
import sys
import pandas as pd
from cryptography.fernet import Fernet, InvalidToken
import getpass
import string
import textwrap
import hashlib as hl

########################################################################
# Echo Server class
########################################################################

class Server:

    # Set the server hostname used to define the server socket address
    # binding. Note that 0.0.0.0 or "" serves as INADDR_ANY. i.e.,
    # bind to all local network interface addresses.
    HOSTNAME = "0.0.0.0"
    PORT = 50000
    RECV_BUFFER_SIZE = 1024
    MAX_CONNECTION_BACKLOG = 10
    MSG_ENCODING = "utf-8"

    # Create server socket address. It is a tuple containing
    # address/hostname and port.
    SOCKET_ADDRESS = (HOSTNAME, PORT)

    def __init__(self):
        self.create_listen_socket()
        self.process_connections_forever()

    def create_listen_socket(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Set socket layer socket options. This allows us to reuse
            # the socket without waiting for any timeouts.
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Bind socket to socket address, i.e., IP address and port.
            self.socket.bind(Server.SOCKET_ADDRESS)

            # Set socket to listen state.
            self.socket.listen(Server.MAX_CONNECTION_BACKLOG)
            print("Listening on port {} ...".format(Server.PORT))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def process_connections_forever(self):
        try:
            while True:
                # Block while waiting for accepting incoming
                # connections. When one is accepted, pass the new
                # (cloned) socket reference to the connection handler
                # function.
                self.connection_handler(self.socket.accept())
        except Exception as msg:
            print(msg)
        except KeyboardInterrupt:
            print()
        finally:
            self.socket.close()
            sys.exit(1)

    def connection_handler(self, client):
        connection, address_port = client
        print("-" * 72)
        print("Connection received from {}.".format(address_port))

        grade_data = 'course_grades.csv'
        grade_df = pd.read_csv(grade_data)


        while True:
            try:
                # Receive bytes over the TCP connection. This will block
                # until "at least 1 byte or more" is available.
                recvd_bytes = connection.recv(Server.RECV_BUFFER_SIZE)
            
                # If recv returns with zero bytes, the other end of the
                # TCP connection has closed (The other end is probably in
                # FIN WAIT 2 and we are in CLOSE WAIT.). If so, close the
                # server end of the connection and get the next client
                # connection.
                if len(recvd_bytes) == 0:
                    print("Closing client connection ... ")
                    connection.close()
                    break
                
                # Decode the received bytes back into strings. Then output
                # them.
                recvd_str = recvd_bytes.decode(Server.MSG_ENCODING)
                cleaned = recvd_str.strip()
                cmd_in = self.get_cmd(cleaned)

                validCmd = ['GMA', 'GL1A', 'GL2A', 'GL3A', 'GL4A', 'GG']

                # Detect incoming SHA-256 hex digest (client sent credentials hash)
                is_hash = (len(cleaned) == 64 and all(c in string.hexdigits for c in cleaned))

                if (len(cmd_in) < 2 or cmd_in not in validCmd) and not is_hash:
                    error_msg = (f"Invalid Command!!! Please enter one of the following commands: [GMA, GL1A, GL2A, GL3A, GL4A, GG] \n"
                                    f"Echo Message: {recvd_str}")
                    connection.sendall(error_msg.encode(Server.MSG_ENCODING))
                    print("Invalid Command\n")

                else:
                    # If client sent a raw hash, handle it as a grades lookup.
                    if is_hash:
                        print("Received hash key from client; verifying...\n")
                        grades = self.verifyHashKey(grade_df, cleaned)

                        if grades is not None:
                            connection.sendall(self.format_grades(grades).encode(Server.MSG_ENCODING))
                        else:
                            error_msg = (f"Login Failed!!! Please Ensure Credentials are correct \n"
                                f"Echo Message: {recvd_str}")
                            connection.sendall(error_msg.encode(Server.MSG_ENCODING))
                            print("Invalid Login\n")
                        continue

                    print(f"Received {cmd_in} command from client \n")

                    if cmd_in == "GMA":
                        print(f"User requested to Get Midterm Average {cmd_in} \n")
                        GMA_data = self.calculate_GMA(grade_df)
                        GMA_bytes = str(f"Midterm Average: {GMA_data:.2f}%").encode(Server.MSG_ENCODING)
                        connection.sendall(GMA_bytes)

                    elif cmd_in == "GL1A":
                        print(f"User requested to Get Lab 1 Average {cmd_in} \n")
                        GL1A_data = self.calculate_GL1A(grade_df)
                        GL1A_bytes = str(f"Lab 1 Average: {GL1A_data:.2f}%").encode(Server.MSG_ENCODING)
                        connection.sendall(GL1A_bytes)

                    elif cmd_in == "GL2A":
                        print(f"User requested to Get Lab 2 Average {cmd_in} \n")
                        GL2A_data = self.calculate_GL2A(grade_df)
                        GL2A_bytes = str(f"Lab 2 Average: {GL2A_data:.2f}%").encode(Server.MSG_ENCODING)
                        connection.sendall(GL2A_bytes)

                    elif cmd_in == "GL3A":
                        print(f"User requested to Get Lab 3 Average {cmd_in} \n")
                        GL3A_data = self.calculate_GL3A(grade_df)
                        GL3A_bytes = str(f"Lab 3 Average: {GL3A_data:.2f}%").encode(Server.MSG_ENCODING)
                        connection.sendall(GL3A_bytes)

                    elif cmd_in == "GL4A":
                        print(f"User requested to Get Lab 4 Average {cmd_in} \n")
                        GL4A_data = self.calculate_GL4A(grade_df)
                        GL4A_bytes = str(f"Lab 4 Average: {GL4A_data:.2f}%").encode(Server.MSG_ENCODING)
                        connection.sendall(GL4A_bytes)

                    else:
                        # If 'GG' text command arrives, respond with guidance
                        if cmd_in == "GG":
                            info_msg = ("To retrieve grades, run the client and enter 'GG',\n"
                                        "which will prompt for username and password and send a hashed key.")
                            connection.sendall(info_msg.encode(Server.MSG_ENCODING))
                        else:
                            print(f"User requested to Get Student Grades {cmd_in} \n")
                            print(f"Checking Hash Key...\n")
                            grades = self.verifyHashKey(grade_df, cleaned)

                            if grades is not None:
                                connection.sendall(self.format_grades(grades).encode(Server.MSG_ENCODING))
                            else:
                                error_msg = (f"Login Failed!!! Please Ensure Credentials are correct \n"
                                    f"Echo Message: {recvd_str}")
                                connection.sendall(error_msg.encode(Server.MSG_ENCODING))
                                print("Invalid Login\n")
            except KeyboardInterrupt:
                print()
                print("Closing client connection ... ")
                connection.close()
                break

    def calculate_GMA(self, gradeDB):
        return gradeDB["Midterm"].mean()

    def calculate_GL1A(self, gradeDB):
        return gradeDB["Lab 1"].mean()

    def calculate_GL2A(self, gradeDB):
        return gradeDB["Lab 2"].mean()

    def calculate_GL3A(self, gradeDB):
        return gradeDB["Lab 3"].mean()

    def calculate_GL4A(self, gradeDB):
        return gradeDB["Lab 4"].mean()
    
    def gethashKey(self, username, password):
        encoded_username = username.encode("utf-8")
        encoded_password = password.encode("utf-8")

        h = hl.new('sha256')
        h.update(encoded_username)
        h.update(encoded_password)

        # Return hex string for safe transport over text protocols
        return h.hexdigest()
    
    
    def verifyHashKey(self, gradeDB, key):
        # If a pandas DataFrame was passed, convert to list of dicts
        if hasattr(gradeDB, "to_dict"):
            records = gradeDB.to_dict("records")
        else:
            records = gradeDB

        # Normalize incoming key to hex string for comparison
        if isinstance(key, bytes):
            try:
                key_str = key.decode("utf-8")
            except Exception:
                key_str = key.hex()
        else:
            key_str = key

        for entry in records:
            uid = str(entry.get("ID Number", ""))
            pwd = str(entry.get("Password", ""))
            check_key = self.gethashKey(uid, pwd)  # returns hex string
            if check_key == key_str:
                return entry
        return None

    def format_grades(self, grades):
        """Return a nicely formatted multi-line string of the student's grades."""
        return textwrap.dedent(f"""\
        Login Verified for {grades['First Name']} {grades['Last Name']}
        {"-"*72}
        Grades for {grades['First Name']} {grades['Last Name']}
        {"-"*72}
        Lab 1 Grade: {grades['Lab 1']}%
        Lab 2 Grade: {grades['Lab 2']}%
        Lab 3 Grade: {grades['Lab 3']}%
        Lab 4 Grade: {grades['Lab 4']}%
        Midterm Grade: {grades['Midterm']}%
        {"-"*72}
        """)
        




        





    def get_cmd(self, recvd_string):
        # Return up to the first 4 characters so commands like 'GL1A' are captured.
        # Shorter commands such as 'GMA' or 'GG' are unaffected.
        return recvd_string.strip().upper()[:4]

########################################################################
# Echo Client class
########################################################################

class Client:

    # Set the server hostname to connect to. If the server and client
    # are running on the same machine, we can use the current
    # hostname.
#    SERVER_HOSTNAME = socket.gethostbyname('localhost')
    SERVER_HOSTNAME = socket.gethostbyname('')
#    SERVER_HOSTNAME = 'localhost'

    RECV_BUFFER_SIZE = 1024

    def __init__(self):
        self.get_socket()
        self.connect_to_server()
        self.send_console_input_forever()

    def get_socket(self):
        try:
            # Create an IPv4 TCP socket.
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connect_to_server(self):
        try:
            # Connect to the server using its socket address tuple.
            self.socket.connect((Client.SERVER_HOSTNAME, Server.PORT))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def get_console_input(self):
        # In this version we keep prompting the user until a non-blank
        # line is entered.
        while True:
            raw = input("Input: ").strip()
            # If user types GG (case-insensitive), prompt for credentials
            if raw.upper() == "GG":
                print("User requested to Get Student Grades\n")
                print("Needs further verification...\n")
                username, password = self.getLoginCreds()
                # gethashKey now returns a hex string; store that so connection_send
                # will send it as text.
                self.input_text = self.gethashKey(username, password)
                break
            # For any other non-empty input, use it as the command/text
            if raw != "":
                self.input_text = raw
                break



    
    def send_console_input_forever(self):
        while True:
            try:
                self.get_console_input()
                self.connection_send()
                self.connection_receive()
            except (KeyboardInterrupt, EOFError):
                print()
                print("Closing server connection ...")
                self.socket.close()
                sys.exit(1)
                
    def connection_send(self):
        try:
            if isinstance(self.input_text, bytes):
                self.socket.sendall(self.input_text)
            else:
                self.socket.sendall(self.input_text.encode(Server.MSG_ENCODING))
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connection_receive(self):
        try:
            # Receive and print out text. The received bytes objects
            # must be decoded into string objects.
            recvd_bytes = self.socket.recv(Client.RECV_BUFFER_SIZE)

            # recv will block if nothing is available. If we receive
            # zero bytes, the connection has been closed from the
            # other end. In that case, close the connection on this
            # end and exit.
            if len(recvd_bytes) == 0:
                print("Closing server connection ... ")
                self.socket.close()
                sys.exit(1)

            resp = recvd_bytes.decode(Server.MSG_ENCODING)
            print("\n----- Server Response -----")
            print(resp)
            print("---------------------------\n")

        except Exception as msg:
            print(msg)
            sys.exit(1)

    def getLoginCreds(self):
        user_name = input("Enter Username: ")
        password = getpass.getpass("Enter Password: ")

        return user_name, password
    
    def gethashKey(self, username, password):
        encoded_username = username.encode("utf-8")
        encoded_password = password.encode("utf-8")

        h = hl.new('sha256')
        h.update(encoded_username)
        h.update(encoded_password)

        # Return hex string for safe transport
        return h.hexdigest()

########################################################################
# Process command line arguments if this module is run directly.
########################################################################

# When the python interpreter runs this module directly (rather than
# importing it into another file) it sets the __name__ variable to a
# value of "__main__". If this file is imported from another module,
# then __name__ will be set to that module's name.

if __name__ == '__main__':
    roles = {'client': Client,'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles, 
                        help='server or client role',
                        required=True, type=str)

    args = parser.parse_args()
    roles[args.role]()

########################################################################






