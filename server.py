import socket
import os
import json
import struct
from encryption import Encryption
from config import HOST, PORT, ENCRYPTION_KEY

class FileServer:
    def __init__(self, host=HOST, port=PORT, key=ENCRYPTION_KEY):
        self.host = host
        self.port = port
        self.encryption = Encryption(key)
        self.storage_dir = 'server_files'
        os.makedirs(self.storage_dir, exist_ok=True)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def start(self):
        try:
            self.socket.bind((self.host, self.port))
            self.socket.listen()
            print(f"Server listening on {self.host}:{self.port}")
            while True:
                conn, addr = self.socket.accept()
                self.handle_client(conn, addr)
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            self.socket.close()

    def receive_message(self, conn):
        raw_msglen = self.recvall(conn, 4)
        if not raw_msglen:
            return None
        msglen = struct.unpack('>I', raw_msglen)[0]
        return self.recvall(conn, msglen)

    def recvall(self, conn, n):
        data = bytearray()
        while len(data) < n:
            packet = conn.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return data

    def send_message(self, conn, data):
        data = self.encryption.encrypt(json.dumps(data))
        length = struct.pack('>I', len(data))
        try:
            conn.sendall(length + data)
            return True
        except (BrokenPipeError, ConnectionResetError):
            return False

    def handle_client(self, conn, addr):
        print(f"Connected to {addr}")
        try:
            while True:
                encrypted_data = self.receive_message(conn)
                if not encrypted_data:
                    break
                try:
                    data = json.loads(self.encryption.decrypt(encrypted_data).decode())
                except (json.JSONDecodeError, UnicodeDecodeError) as e:
                    print(f"Invalid data from {addr}: {e}")
                    self.send_message(conn, {'status': 'error', 'message': f'Invalid data format: {e}'})
                    break

                command = data.get('command')
                if not command:
                    self.send_message(conn, {'status': 'error', 'message': 'No command specified'})
                    break

                if command == 'list':
                    try:
                        files = os.listdir(self.storage_dir)
                        print(f"Listing files in {self.storage_dir}: {files}")  # Debug log
                        response = {'files': files, 'status': 'success'}
                    except Exception as e:
                        print(f"Failed to list files: {e}")
                        response = {'status': 'error', 'message': f'Failed to list files: {str(e)}'}
                    if not self.send_message(conn, response):
                        break

                elif command == 'download':
                    filename = data.get('filename')
                    if not filename:
                        response = {'status': 'error', 'message': 'No filename provided'}
                    else:
                        try:
                            with open(os.path.join(self.storage_dir, filename), 'rb') as f:
                                file_data = f.read()
                            response = {'data': file_data.hex(), 'status': 'success'}
                        except FileNotFoundError:
                            response = {'status': 'error', 'message': 'File not found'}
                        except Exception as e:
                            response = {'status': 'error', 'message': f'Download error: {str(e)}'}
                    if not self.send_message(conn, response):
                        break

                elif command == 'delete':
                    filename = data.get('filename')
                    if not filename:
                        response = {'status': 'error', 'message': 'No filename provided'}
                    else:
                        try:
                            os.remove(os.path.join(self.storage_dir, filename))
                            response = {'status': 'success'}
                        except FileNotFoundError:
                            response = {'status': 'error', 'message': 'File not found'}
                        except Exception as e:
                            response = {'status': 'error', 'message': f'Delete error: {str(e)}'}
                    if not self.send_message(conn, response):
                        break

                else:
                    self.send_message(conn, {'status': 'error', 'message': 'Invalid command'})
                    break

        except (ConnectionResetError, BrokenPipeError):
            print(f"Client {addr} disconnected")
        except Exception as e:
            print(f"Error handling client {addr}: {e}")
        finally:
            conn.close()
            print(f"Connection to {addr} closed")

if __name__ == '__main__':
    server = FileServer()
    server.start()