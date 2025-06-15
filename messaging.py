import json
import struct

class MessageHandler:
    def __init__(self, encryption):
        self.encryption = encryption

    def recvall(self, conn, n):
        data = bytearray()
        while len(data) < n:
            packet = conn.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return data

    def receive_message(self, conn):
        raw_msglen = self.recvall(conn, 4)
        if not raw_msglen:
            return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        return self.recvall(conn, msglen)

    def send_message(self, conn, data):
        data = self.encryption.encrypt(json.dumps(data))
        length = struct.pack('>I', len(data))
        try:
            conn.sendall(length + data)
            return True
        except (BrokenPipeError, ConnectionResetError):
            return False
