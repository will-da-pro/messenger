import socket
from threading import Thread

from packets import Packet

HOST = input("Server address: ")
PORT = 64646  # The port used by the server

def execute_command(conn: socket.socket, command: str) -> None:
    commands: dict[str, str] = {
        "help": "Display this menu",
        "leave": "Leave the current chat"
    }

    args: list[str] = command.split(" ")

    if args[0] == "help":
        print("Available Commands:")

        for cmd, info in commands.items():
            print(f"- /{cmd}: {info}")

        server_command_packet = Packet(5, "commands")
        conn.send(server_command_packet.encode())

    elif args[0] == "leave":
        leave_packet = Packet(5, "leave")
        conn.send(leave_packet.encode())
        conn.close()
        exit()

    else:
        command_packet = Packet(4, command)
        conn.send(command_packet.encode())

def receive_messages(s: socket.socket) -> None:
    while True:
        try:
            data = s.recv(1024)

            if not data:
                break

            packets_str = data.decode()
            raw_packets: list[str] = packets_str.split(chr(4))

            for raw_packet in raw_packets:
                if len(raw_packet) == 0:
                    continue

                packet = Packet.decode(raw_packet)

                if packet.type == 2:
                    print(packet.content)

                elif packet.type == 3:
                    if packet.content == 1:
                        print("Message too long! (>100)")

                    elif packet.content == 2:
                        print("Command not found!")
                    
                    else:
                        raise Exception(packet.content)

        except OSError:
            print("Disconnected")
            return

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    name = input("Please enter your name: ")
    name_packet = Packet(1, name)

    thread = Thread(target=receive_messages, args=(s,))
    thread.start()

    s.send(name_packet.encode())

    while True:
        msg = input("")

        if len(msg) == 0:
            continue

        if msg[0] == '/':
            execute_command(s, msg[1:])

        else:    
            packet = Packet(2, msg)

            s.send(packet.encode())
