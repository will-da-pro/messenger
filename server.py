import socket
from threading import Thread

from packets import InvalidPacketException, Packet

PORT = 64646

class User:
    def __init__(self, name: str, conn: socket.socket, addr, privileged: float = False) -> None:
        self.name: str = name

        self.conn: socket.socket = conn
        self.addr = addr

        self.privileged: float = privileged

    def handle_message(self, message: str) -> None:
        if len(message) > 100:
            error_packet = Packet(3, 1)
            conn.send(error_packet.encode())
            return

        broadcast_str = f"<{self.name}> {message}"
        broadcast(broadcast_str)

    def handle_command(self, command: str) -> None:
        args: list[str] = command.split(" ")

        if args[0] == "ping":
            reply_packet = Packet(2, "pong")
            self.conn.send(reply_packet.encode())

        elif not self.privileged:
            error_packet = Packet(3, 2)
            self.conn.send(error_packet.encode())

        elif args[0] == "kick":
            pass

        elif args[0] == "ban":
            pass

        elif args[0] == "unban":
            pass

        else:
            error_packet = Packet(3, 2)
            self.conn.send(error_packet.encode())

    def handle_request(self, request: str) -> None:
        if request == "commands":
            self.commands: dict[str, str] = {
                "ping": "Check connection to the server"
            }

            self.privileged_commands: dict[str, str] = {
                "kick": "Kick a user from the server",
                "ban": "Ban a user from the server",
                "unban": "Unban a user from the server"
            }

            for cmd, info in self.commands.items():
                packet = Packet(2, f"- /{cmd}: {info}")
                self.conn.send(packet.encode())

            if self.privileged: 
                for cmd, info in self.privileged_commands.items():
                    packet = Packet(2, f"- /{cmd}: {info}")
                    self.conn.send(packet.encode())

        elif request == "leave":
            self.conn.close()

    def receive_messages(self) -> None:
        while True:
            try:
                raw_data = self.conn.recv(1024)

                if not raw_data:
                    return

                packets_str = raw_data.decode()
                raw_packets = packets_str.split(chr(4))

                for raw_packet in raw_packets:
                    if len(raw_packet) == 0:
                        continue
                    
                    try:
                        packet = Packet.decode(raw_packet)

                    except InvalidPacketException:
                        continue

                    if packet.type == 2:
                        message: str = str(packet.content)

                        self.handle_message(message)

                    elif packet.type == 4:
                        command = str(packet.content)

                        self.handle_command(command)

                    elif packet.type == 5:
                        request: str = str(packet.content)

                        self.handle_request(request)

            except OSError:
                self.conn.close()
                broadcast(f"User {self.name} has left the chat.")
                return
                    
    def __del__(self):
        self.conn.close()

users: dict[str, User] = {}
banned_users: dict[str, str] = {}

def broadcast(message: str) -> None:
    packet = Packet(2, message)
    print(message)

    for name, user in list(users.items()):
        try:
            user.conn.send(packet.encode())
        except:
            del users[name]
            broadcast(f"User {name} disconnected.")

def new_client(conn: socket.socket, addr) -> None:
    raw_data: bytes = conn.recv(1024)

    raw_str = raw_data.decode()
    raw_packets: list[str] = raw_str.split(chr(4))

    for raw_packet in raw_packets:
        if len(raw_packet) == 0:
            continue
    
        packet = Packet.decode(raw_packet)
        name: str = str(packet.content)

        if packet.type != 1:
            error_packet = Packet(3, "Name not set!")
            conn.send(error_packet.encode())
            conn.close()
            return
        
        if not 2 < len(name) < 16:
            error_packet = Packet(3, "Name must be between 3 and 15 characters!")
            conn.send(error_packet.encode())
            conn.close()
            return

        if not name.isalnum():
            error_packet = Packet(3, "Name must not contain any special characters!")
            conn.send(error_packet.encode())
            conn.close()
            return

        if name in users.keys():
            error_packet = Packet(3, "Name already in use!")
            conn.send(error_packet.encode())
            conn.close()
            return

        privileged = False
        if addr[0] == '127.0.0.1':
            privileged = True

        user = User(name, conn, addr, privileged)
        users[name] = user

        join_message = f"User {name} has joined the chat."
        broadcast(join_message)

        welcome_packet = Packet(2, f"Welcome, {name}")
        conn.send(welcome_packet.encode())

        user.receive_messages()

local_name = socket.gethostname()
local_ip = socket.gethostbyname_ex(local_name)[-1]

print(local_ip)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(("", PORT))
    s.listen()

    while True:
        conn, addr = s.accept()

        print(f"New connection from {addr}")
        
        thread = Thread(target=new_client, args=(conn, addr))
        thread.start()
