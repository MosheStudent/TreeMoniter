# TreeMoniter

![TreeMoniter Logo](logo.png)

## Description

**TreeMoniter** is a cross-platform client-server application that allows you to remotely monitor and manage files and folders on another computer over a network, with a graphical interface. It provides a secure way to browse directories, download files, and manage file systems remotely.

- **Server**: Runs on the remote machine you want to monitor. Handles file listing, downloads, and deletion requests from clients.
- **Client**: Provides a graphical interface to connect to the server, browse directories, download files, and manage the remote file system.

## Features

- List files and directories on a remote computer in real time.
- Navigate into directories or go up to parent directories.
- Download files from the remote server.
- Delete files remotely (with confirmation).
- Secure communication using encryption.
- Simple and intuitive Tkinter-based GUI for clients.

## How It Works

- The server listens for incoming connections and processes requests for file operations.
- The client connects to the server using the provided host and port, then authenticates and encrypts communication.
- The client GUI allows you to:
  - Connect to/disconnect from the server.
  - Browse and navigate the remote file system.
  - Download or delete selected files.

## How to Run

**Prerequisites**:
- Python 3.x is required on both server and client machines.
- All dependencies listed in `requirements.txt` (if available) should be installed.

### 1. Setup

Clone the repository on both the server and client machines:
```bash
git clone https://github.com/MosheStudent/TreeMoniter.git
cd TreeMoniter
```

### 2. Configuration

Edit the `config.py` file to set:
- `HOST`: The IP address of the server (for the client to connect to).
- `PORT`: The port number for communication.
- `ENCRYPTION_KEY`: The shared encryption key for secure communication.

### 3. Running the Server

On the remote machine you want to monitor, run:
```bash
python server.py
```

### 4. Running the Client

On your local machine, run:
```bash
python client.py
```

A graphical window will appear allowing you to connect to the server and browse/download/delete remote files.

## Security

All communication between client and server is encrypted using the provided key, ensuring that file operations and data transfers remain secure.

---

*For more details, see the source code in `server.py`, `client.py`, and `client_gui.py`.*