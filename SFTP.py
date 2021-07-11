# Simple File Tranfer Protocol (TCP)
#
#|----------- Packet -----------|
#|          VERSION(1B)         |
#|  NAME_CHARACTERS_AMOUNT(2B)  |
#|         FILE_SIZE(4B)        |
#|          FILE_NAME           |
#|          FILE_DATA           |
#|------------------------------|

# Simple File Transfer Protocol - Simple Service Discovery Protocol (UDP)
#
#|-------- Packet --------|
#|       VERSION(1B)      |
#|        TYPE(1B)        |
#|        NAME(16B)       |
#|        PORT(2B)        |
#|------------------------|
# Type: Discover(0), Response(1), BadRequest(2)

# Add SSFTP (Secure Simple File Transfer Protocol)

from __future__ import annotations
from io import BufferedWriter
import socket
import os
import struct
import argparse
import threading
import abc
from typing import Dict, NamedTuple, Union

SFTP_VERSION = 1
SFTP_BUFFER_SIZE = 8192

class Address(NamedTuple):
    ip: str
    port: int

class SSDP:
    SSDP_VERSION = 1
    SSDP_MULTICAST = '239.255.255.250'
    SSDP_PORT = 12000
    _sock: socket.socket
    _service_name: bytes
    _service_port: int
    _service_thread: Union[threading.Thread, None]
    _service_event: Union[threading.Event, None]
    def __init__(self, name: str, port: int):
        self._service_name = struct.pack('16s', name.encode('UTF-8'))
        self._service_port = port
        self._service_thread = None
        self._service_event = None
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setblocking(False)
        self._sock.bind(('', self.SSDP_PORT))
        group = socket.inet_aton(self.SSDP_MULTICAST)
        mreq = struct.pack('4sL', group, socket.INADDR_ANY)
        self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    def loop(self) -> None:
        try:
            packet, addr = self._sock.recvfrom(18)
        except (BlockingIOError, OSError):
            return
        header = packet[:2]
        data = packet[2:]
        version: int;type: int;name: bytes
        try:
            version, type = struct.unpack('BB', header)
            if (version == self.SSDP_VERSION and type == 0):
                name, = struct.unpack('16s', data)
                if (name == self._service_name):
                    response = struct.pack('BB16sH', self.SSDP_VERSION, 1,
                        self._service_name, self._service_port)
                    self._sock.sendto(response, addr)
            else:
                response = struct.pack('BB', self.SSDP_VERSION, 2)
                self._sock.sendto(response, addr)
        except struct.error:
            response = struct.pack('BB', self.SSDP_VERSION, 2)
            self._sock.sendto(response, addr)
    def _inf_loop(self):
        self._service_event = threading.Event()
        self._sock.setblocking(True)
        while (not self._service_event.is_set()):
            self.loop()
    def start(self) -> None:
        self._service_thread = threading.Thread(target=self._inf_loop, daemon=True)
        self._service_thread.start()
    def close(self) -> None:
        self._sock.close()
        if (self._service_thread and self._service_event):
            self._service_event.set()
            self._service_thread.join()
    @classmethod
    def find_service(cls, name: str, timeout: Union[float, None] = None) -> Union[Address, None]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        request = struct.pack('BB16s', cls.SSDP_VERSION, 0, name.encode('UTF-8'))
        try:
            sock.sendto(request, (cls.SSDP_MULTICAST, cls.SSDP_PORT))
            response, addr = sock.recvfrom(20)
        except socket.timeout:
            sock.close()
            return None
        sock.close()
        version, type = struct.unpack('BB', response[:2])
        if (version == cls.SSDP_VERSION and type == 1):
            res_name, res_port = struct.unpack('16sH', response[2:])
            if (res_name == request[2:]):
                return Address(addr[0], res_port)
        return None

class SFTP(metaclass=abc.ABCMeta):
    SFTP_VERSION = 1
    SFTP_BUFFER_SIZE = 8192
    _sock: socket.socket
    def __init__(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    def close(self):
        self._sock.close()

class SFTPSender(SFTP):
    def connect(self, host: str, port: int, timeout: Union[float, None] = None) -> bool:
        self._sock.settimeout(timeout)
        try:
            self._sock.connect((host, port))
        except socket.timeout:
            return False
        return True
    def connectFriendly(self, name: str, timeout: Union[float, None] = None) -> bool:
        address = SSDP.find_service(name, timeout)
        if (address):
            return self.connect(address.ip, address.port, timeout)
        return False
    def sendFile(self, filename: str, timeout: Union[float, None] = None) -> None:
        self._sock.settimeout(timeout)
        stat = os.stat(filename)
        file = open(filename, 'rb')
        # Pack the packet
        filename_bytes = filename.encode('UTF-8')
        data = struct.pack('BHi', SFTP_VERSION, len(filename_bytes), stat.st_size)
        self._sock.sendall(data)
        # Send filename
        self._sock.sendall(filename_bytes)
        # Send file
        total_send_amount = 0
        data = file.read(SFTP_BUFFER_SIZE)
        while data:
            send_amount = self._sock.send(data)
            if (len(data) > send_amount):
                data = data[send_amount:]
            else:
                total_send_amount += len(data)
                data = file.read(SFTP_BUFFER_SIZE)
            print(f'\r[{round(total_send_amount / stat.st_size * 100, 2)}%]', end=None)
        print()
        file.close()

class SFTPReceiver(SFTP):
    def __init__(self, port: int = 0):
        super().__init__()
        self._sock.bind(('', port))
        self._sock.listen()
    def _print(self, message: str, end: Union[str, None] = None) -> None:
        print(message, end=end)
    def _receive_file(self, conn_sock: socket.socket, alternativeFilename: Union[str, None], timeout: Union[float, None]) -> None:
        conn_sock.settimeout(timeout)
        # Version, File size, Filename characters count
        data = conn_sock.recv(8)
        version, filename_characters_amount, file_size = struct.unpack('BHi', data)
        if (version != SFTP_VERSION):
            raise Exception('Unsupported protocol version')
        # Filename
        filename = conn_sock.recv(filename_characters_amount).decode('UTF-8')
        # Open file
        file: BufferedWriter
        try:
            file = open(filename, 'xb')
        except FileExistsError as e:
            if (not alternativeFilename):
                raise e
            file = open(alternativeFilename, 'xb')
        # Download file
        received_amount = 0
        data = conn_sock.recv(SFTP_BUFFER_SIZE)
        while data:
            received_amount += len(data)
            file.write(data)
            data = conn_sock.recv(SFTP_BUFFER_SIZE)
            self._print(f'\r[{round(received_amount / file_size * 100, 2)}%]', end=None)
        self._print('')
        file.close()
        conn_sock.close()
    def _receive_multiple_files(self, conn_sock: socket.socket, amount: int, timeout: Union[float, None]) -> None:
        while amount:
            amount -= 1
            self._receive_file(conn_sock, None, timeout)
    def _receive_sock(self, timeout: Union[float, None] = None) -> socket.socket:
        self._sock.settimeout(timeout)
        self._print(f'Listening on {self._sock.getsockname()[1]}')
        conn_sock, conn_addr = self._sock.accept()
        self._print(f'Connected: {(socket.gethostbyaddr(conn_addr[0])[0], *conn_addr)}')
        return conn_sock
    def _receive_friendly_sock(self, name: str, timeout: Union[float, None] = None) -> socket.socket:
        self._sock.settimeout(timeout)
        port = self._sock.getsockname()[1]
        service = SSDP(name, port)
        service.start()
        conn_sock, conn_addr = self._sock.accept()
        self._print(f'Connected: {(socket.gethostbyaddr(conn_addr[0])[0], *conn_addr)}')
        service.close()
        return conn_sock
    def receive(self, alternativeFilename: Union[str, None] = None, timeout: Union[float, None] = None) -> None:
        conn_sock = self._receive_sock(timeout)
        self._receive_file(conn_sock, alternativeFilename, timeout)
    def receiveFriendly(self, name: str, alternativeFilename: Union[str, None] = None, timeout: Union[float, None] = None) -> None:
        conn_sock = self._receive_friendly_sock(name, timeout)
        self._receive_file(conn_sock, alternativeFilename, timeout)
    def receiveMultiple(self, amount: int, timeout: Union[float, None] = None) -> None:
        conn_sock = self._receive_sock(timeout)
        self._receive_multiple_files(conn_sock, amount, timeout)
    def receiveFriendlyMultiple(self, name: str, amount: int, timeout: Union[float, None] = None) -> None:
        conn_sock = self._receive_friendly_sock(name, timeout)
        self._receive_multiple_files(conn_sock, amount, timeout)

class ThreadingSFTPReceiver(SFTPReceiver):
    _MAIN_THREAD_ID = threading.main_thread().ident
    _thread_messages: Dict[int, str]
    _print_lock: threading.Lock
    def __init__(self, port: int = 0):
        super().__init__(port)
        self._thread_messages = {}
        self._print_lock = threading.Lock()
    def _print(self, message: str, end: Union[str, None] = None) -> None:
        thread_id = threading.get_ident()
        with self._print_lock:
            if (thread_id == self._MAIN_THREAD_ID):
                print('\r', message)
            else:
                self._thread_messages[thread_id] = message
            print('\r', self._thread_messages.values(), end=end)
    def treceive(self, accept: int = 1, alternativeFilename: Union[str, None] = None, timeout: Union[float, None] = None) -> None:
        self._sock.settimeout(timeout)
        self._print(f'Listening on {self._sock.getsockname()[1]}')
        while accept:
            accept -= 1
            try:
                conn_sock, conn_addr = self._sock.accept()
            except socket.timeout:
                continue
            self._print(f'Connected: {(socket.gethostbyaddr(conn_addr[0])[0], *conn_addr)}')
            thread = threading.Thread(target=self._receive_file, args=(conn_sock, alternativeFilename, timeout), daemon=True)
            thread.start()
    def treceiveFriendly(self, name: str, accept: int = 1, alternativeFilename: Union[str, None] = None, timeout: Union[float, None] = None) -> None:
        self._sock.settimeout(timeout)
        port = self._sock.getsockname()[1]
        service = SSDP(name, port)
        service.start()
        while accept:
            accept -= 1
            try:
                conn_sock, conn_addr = self._sock.accept()
            except socket.timeout:
                continue
            self._print(f'Connected: {(socket.gethostbyaddr(conn_addr[0])[0], *conn_addr)}')
            thread = threading.Thread(target=self._receive_file, args=(conn_sock, alternativeFilename, timeout), daemon=True)
            thread.start()
        service.close()

def isIP(addr: str) -> bool:
    try:
        socket.inet_aton(addr)
        return True
    except socket.error:
        return False

def main():
    parser = argparse.ArgumentParser(description="Simple File Transfer Protocol",
        conflict_handler='resolve')
    parser.add_argument('-m --mode', dest='mode', choices=['send', 'receive'],
        help='Set mode')
    parser.add_argument('-t', '--timeout', type=int, dest='timeout',
        help='Set timeout(in seconds)')
    parser.add_argument('-p', '--port', type=int, dest='port',
        help='Set port')
    parser.add_argument('-h', '--host', type=str, dest='host',
        help='SEND_MODE: (IP or Friendly name) to send to | RECEIVE_MODE: Friendly name to use')
    parser.add_argument('-f', '--file', type=str, dest='filename',
        help='SEND_MODE: Name of file to send | RECEIVE_MODE: Override received file name')
    parser.add_argument('-zf', '--zip-file', action='store_true', dest='zipfile',
        help='SEND_MODE: File/Directory to zip before sending | RECEIVE_MODE: Unzip data after receiving')
    args = parser.parse_args()
    if (args.mode == 'send'):
        if (args.filename):
            if (isIP(args.host)):
                if (not args.port):
                    raise Exception('No port specified')
                sender = SFTPSender()
                if (sender.connect(args.host, args.port, args.timeout)):
                    sender.sendFile(args.filename, args.timeout)
                else:
                    sender.close()
                    raise Exception('Unable to connect')
                sender.close()
            else:
                sender = SFTPSender()
                if (sender.connectFriendly(args.host, args.timeout)):
                    sender.sendFile(args.filename, args.timeout)
                else:
                    sender.close()
                    raise Exception('Unable to connect')
                sender.close()
        else:
            raise Exception('No file specified')
    elif (args.mode == 'receive'):
        if (not args.port):
            args.port = 0
        if (isIP(args.host)):
            receiver = SFTPReceiver(args.port)
            receiver.receive(args.filename, args.timeout)
            receiver.close()
        else:
            receiver = SFTPReceiver(args.port)
            receiver.receiveFriendly(args.host, args.filename, args.timeout)
            receiver.close()
    else:
        raise Exception('Unknown mode')

if __name__ == '__main__':
    main()
