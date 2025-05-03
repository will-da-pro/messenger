import json
import hashlib

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
        print(data_str)
        data = json.loads(data_str)

        type: int | None = data.get("type")
        content: str | None = data.get("content")
        hash: str | None = data.get("hash")

        if type is None or content is None or hash is None:
            raise Exception("Invalid Packet")

        hash_check = hashlib.sha256(str(content).encode()).hexdigest()

        if hash != hash_check:
            raise Exception("Packet data does not match hash")

        packet = cls(type, content)
        return packet



