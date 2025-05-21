import json
import hashlib

class InvalidPacketException(Exception):
    def __init__(self, message: str):
        self.message = message

class Packet:
    """
    Packet Types:
    - 1: Connect
    - 2: Send Message
    - 3: Error
    - 4: Command
    - 5: Request
    """
    def __init__(self, type: int, content: int | str) -> None:
        self.type: int = type
        self.content: int | str = content

    def encode(self) -> bytes:
        hash = hashlib.sha256(str(self.content).encode()).hexdigest()

        self.content = str(self.content).replace(chr(4), "")

        data: dict[str, int | str] = {
            "type": self.type,
            "content": self.content,
            "hash": hash
        }

        data_str = json.dumps(data)
        data_str += chr(4)
        encoded_data = data_str.encode()
        return encoded_data

    @classmethod
    def decode(cls, data_str: str):
        try:
            data = json.loads(data_str)

        except:
            raise InvalidPacketException("Invalid JSON")

        type: int | None = data.get("type")
        content: str | None = data.get("content")
        hash: str | None = data.get("hash")

        if type is None or content is None or hash is None:
            raise InvalidPacketException("Invalid Packet")

        hash_check = hashlib.sha256(str(content).encode()).hexdigest()

        if hash != hash_check:
            raise InvalidPacketException("Packet data does not match hash")

        packet = cls(type, content)
        return packet

