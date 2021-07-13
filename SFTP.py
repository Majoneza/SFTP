# Simple File Tranfer Protocol (TCP)
#
#|----------- Packet -----------|
#|          VERSION(1B)         |
#|  NAME_CHARACTERS_AMOUNT(2B)  |
#|         FILE_SIZE(8B)        |
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
import socket
import os
import struct
import argparse
import threading
import abc
import shutil
from typing import Callable, ClassVar, Dict, Final, Generator, List, NamedTuple, TypeVar, Union

SFTP_VERSION = 1
SFTP_BUFFER_SIZE = 8192

T = TypeVar('T')
class CustomList(List[T]):
    def popper(self, __index: int) -> Union[T, None]:
        if (len(self) > 0):
            return self.pop(__index)
        return None

class Address(NamedTuple):
    ip: str
    port: int

class SSDP:
    class SSDP_TYPE:
        DISCOVER = 0
        RESPONSE = 1
        BAD_REQUEST = 2
    SSDP_VERSION: Final[int] = 1
    SSDP_MULTICAST: Final[str] = '239.255.255.250'
    SSDP_PORT: Final[int] = 12000
    _sock: socket.socket
    _service_name: bytes
    _service_port: int
    _service_thread: Union[threading.Thread, None]
    _service_event: Union[threading.Event, None]
    def __init__(self, name: str, port: int):
        self._service_name = struct.pack('!16s', name.encode('UTF-8'))
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
            data, addr = self._sock.recvfrom(18)
        except (BlockingIOError, BrokenPipeError, OSError):
            return None
        if (addr):
            try:
                version, type, name = struct.unpack('!BB16s', data)
                if (version == self.SSDP_VERSION and type == self.SSDP_TYPE.DISCOVER
                        and name == self._service_name):
                    response = struct.pack('!BB16sH', self.SSDP_VERSION,
                        self.SSDP_TYPE.RESPONSE, self._service_name, self._service_port)
                    self._sock.sendto(response, addr)
            except struct.error:
                response = struct.pack('!BB16sH', self.SSDP_VERSION,
                    self.SSDP_TYPE.BAD_REQUEST, b'', 0)
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
        if (self._service_event):
            self._service_event.set()
        self._sock.shutdown(socket.SHUT_RD)
        self._sock.close()
        if (self._service_thread):
            self._service_thread.join()
    @classmethod
    def find_service(cls, name: str, timeout: Union[float, None] = None) -> Union[Address, None]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        request = struct.pack('!BB16s', cls.SSDP_VERSION,
            cls.SSDP_TYPE.DISCOVER, name.encode('UTF-8'))
        try:
            sock.sendto(request, (cls.SSDP_MULTICAST, cls.SSDP_PORT))
            response, addr = sock.recvfrom(20)
        except socket.timeout:
            sock.close()
            return None
        sock.close()
        try:
            version, type, res_name, res_port = struct.unpack('!BB16sH', response)
        except struct.error:
            return None
        if (version == cls.SSDP_VERSION and type == cls.SSDP_TYPE.RESPONSE
                and res_name == request[2:]):
            return Address(addr[0], res_port)
        return None

class SFTP(metaclass=abc.ABCMeta):
    SFTP_VERSION: Final[int] = 1
    SFTP_BUFFER_SIZE: Final[int] = 8192
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
        data = struct.pack('!BHQ', SFTP_VERSION, len(filename_bytes), stat.st_size)
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
            print(f'\r[{round(total_send_amount / stat.st_size * 100, 2)}%]', end='')
        print()
        file.close()
    def sendZip(self, filename: str, timeout: Union[float, None] = None) -> None:
        new_filename = shutil.make_archive(filename, 'zip')
        self.sendFile(new_filename, timeout)

class SFTPReceiver(SFTP):
    def __init__(self, port: int = 0):
        super().__init__()
        self._sock.bind(('', port))
        self._sock.listen()
    def _print(self, message: str, end: Union[str, None] = '\n') -> None:
        print(message, end=end)
    def _receive_file(self, conn_sock: socket.socket, overrideFilename: Union[str, None], timeout: Union[float, None]) -> str:
        conn_sock.settimeout(timeout)
        # Version, File size, Filename characters count
        data = conn_sock.recv(11)
        version, filename_characters_amount, file_size = struct.unpack('!BHQ', data)
        if (version != SFTP_VERSION):
            raise Exception('Unsupported protocol version')
        # Filename
        filename = conn_sock.recv(filename_characters_amount).decode('UTF-8')
        # Override filename
        if (overrideFilename):
            filename = overrideFilename
        # Open file
        file = open(filename, 'xb')
        # Download file
        received_amount = 0
        data = conn_sock.recv(SFTP_BUFFER_SIZE)
        while data:
            received_amount += len(data)
            file.write(data)
            data = conn_sock.recv(SFTP_BUFFER_SIZE)
            self._print(f'\r[{round(received_amount / file_size * 100, 2)}%]', end='')
        self._print('')
        file.close()
        conn_sock.close()
        return filename
    def _receive_multiple_files(self, conn_sock: socket.socket, amount: int, overrideFilenames: Union[List[str], None], timeout: Union[float, None]) -> None:
        if (overrideFilenames):
            overrideFilenames = CustomList(filter(lambda x: x != '', overrideFilenames))
        else:
            overrideFilenames = CustomList()
        while amount:
            amount -= 1
            filename = overrideFilenames.popper(0)
            self._receive_file(conn_sock, filename, timeout)
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
    def _gen_receive_sock(self, accept: int, timeout: Union[float, None] = None) -> Generator[socket.socket, None, None]:
        self._sock.settimeout(timeout)
        self._print(f'Listening on {self._sock.getsockname()[1]}')
        while accept:
            accept -= 1
            try:
                conn_sock, conn_addr = self._sock.accept()
            except socket.timeout:
                continue
            self._print(f'Connected: {(socket.gethostbyaddr(conn_addr[0])[0], *conn_addr)}')
            yield conn_sock
    def _gen_receive_friendly_sock(self, name: str, accept: int, timeout: Union[float, None] = None) -> Generator[socket.socket, None, None]:
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
            yield conn_sock
        service.close()
    def receive(self, overrideFilename: Union[str, None] = None, timeout: Union[float, None] = None) -> None:
        conn_sock = self._receive_sock(timeout)
        self._receive_file(conn_sock, overrideFilename, timeout)
    def receiveFriendly(self, name: str, overrideFilename: Union[str, None] = None, timeout: Union[float, None] = None) -> None:
        conn_sock = self._receive_friendly_sock(name, timeout)
        self._receive_file(conn_sock, overrideFilename, timeout)
    def receiveZip(self, overrideFilename: Union[str, None] = None, timeout: Union[float, None] = None) -> None:
        conn_sock = self._receive_sock(timeout)
        filename = self._receive_file(conn_sock, overrideFilename, timeout)
        shutil.unpack_archive(filename, format='zip')
    def receiveFriendlyZip(self, name: str, overrideFilename: Union[str, None] = None, timeout: Union[float, None] = None) -> None:
        conn_sock = self._receive_friendly_sock(name, timeout)
        filename = self._receive_file(conn_sock, overrideFilename, timeout)
        shutil.unpack_archive(filename, format='zip')
    def receiveMultiple(self, amount: int, overrideFilenames: Union[List[str], None] = None, timeout: Union[float, None] = None) -> None:
        conn_sock = self._receive_sock(timeout)
        self._receive_multiple_files(conn_sock, amount, overrideFilenames, timeout)
    def receiveMultipleFriendly(self, name: str, amount: int, overrideFilenames: Union[List[str], None] = None, timeout: Union[float, None] = None) -> None:
        conn_sock = self._receive_friendly_sock(name, timeout)
        self._receive_multiple_files(conn_sock, amount, overrideFilenames, timeout)

class ThreadingSFTPReceiver(SFTPReceiver):
    _MAIN_THREAD_ID: ClassVar[Union[int, None]] = threading.main_thread().ident
    _thread_messages: Dict[int, str]
    _print_lock: threading.Lock
    def __init__(self, port: int = 0):
        super().__init__(port)
        self._thread_messages = {}
        self._print_lock = threading.Lock()
    def _print(self, message: str, end: Union[str, None] = '\n') -> None:
        thread_id = threading.get_ident()
        with self._print_lock:
            if (thread_id == self._MAIN_THREAD_ID):
                print('\r', message)
            else:
                self._thread_messages[thread_id] = message
            print('\r', self._thread_messages.values(), end=end)
    def treceive(self, accept: int, overrideFilename: Union[str, None] = None, timeout: Union[float, None] = None) -> None:
        for conn_sock in self._gen_receive_sock(accept, timeout):
            thread = threading.Thread(target=self._receive_file, args=(conn_sock, overrideFilename, timeout), daemon=True)
            thread.start()
    def treceiveFriendly(self, name: str, accept: int, overrideFilename: Union[str, None] = None, timeout: Union[float, None] = None) -> None:
        for conn_sock in self._gen_receive_friendly_sock(name, accept, timeout):
            thread = threading.Thread(target=self._receive_file, args=(conn_sock, overrideFilename, timeout), daemon=True)
            thread.start()
    def treceiveMultiple(self, accept: int, amount: int, overrideFilenames: Union[List[str], None] = None, timeout: Union[float, None] = None) -> None:
        for conn_sock in self._gen_receive_sock(accept, timeout):
            thread = threading.Thread(target=self._receive_multiple_files, args=(conn_sock, amount, overrideFilenames, timeout), daemon=True)
            thread.start()
    def treceiveMultipleFriendly(self, name: str, accept: int, amount: int, overrideFilenames: Union[List[str], None] = None, timeout: Union[float, None] = None) -> None:
        for conn_sock in self._gen_receive_friendly_sock(name, accept, timeout):
            thread = threading.Thread(target=self._receive_file, args=(conn_sock, amount, overrideFilenames, timeout), daemon=True)
            thread.start()

def isIP(addr: str) -> bool:
    try:
        socket.inet_aton(addr)
        return True
    except socket.error:
        return False

class pint(int):
    def __new__(cls, x: Union[str, bytes, bytearray]):
        if (int(x) <= 0):
            raise ValueError()
        return super().__new__(cls, x)

class nnint(int):
    def __new__(cls, x: Union[str, bytes, bytearray]):
        if (int(x) < 0):
            raise ValueError()
        return super().__new__(cls, x)

def main():
    parser = argparse.ArgumentParser(description="Simple File Transfer Protocol",
        conflict_handler='resolve')
    parser.add_argument('-s', '--send', action='store_true', dest='send',
        help='Set mode to SEND')
    parser.add_argument('-r', '--receive', action='store_true', dest='receive',
        help='Set mode to RECEIVE')
    parser.add_argument('-t', '--timeout', type=nnint, dest='timeout',
        help='Set timeout(in seconds)')
    parser.add_argument('-p', '--port', type=nnint, dest='port',
        help='SEND_MODE: Port to send to | RECEIVE_MODE: Port to bind to')
    parser.add_argument('-h', '--host', type=str, dest='host',
        help='SEND_MODE: (IP or Friendly name) to send to')
    parser.add_argument('-n', '--name', type=str, dest='name',
        help='RECEIVE_MODE: Friendly name to use')
    parser.add_argument('-a', '--accept', type=pint, default=1, dest='accept',
        help='RECEIVE_MODE: How many connections to accept (default=1)')
    parser.add_argument('-c', '--count', type=pint, default=1, dest='count',
        help='RECEIVE_MODE: How many files to receive (default=1)')
    parser.add_argument('-d', '--dir', type=str, default='./', dest='dir',
        help='Set root directory(default=\'./\')')
    parser.add_argument('-zf', '--zip-file', action='store_true', dest='zipfile',
        help='SEND_MODE: File(s)/Directory to zip before sending | RECEIVE_MODE: Unzip data after receiving')
    parser.add_argument('files', type=str, nargs='*',
        help='SEND_MODE: Name of file(s) to send | RECEIVE_MODE: Override received file(s) name')
    args = parser.parse_args()
    os.chdir(args.dir)
    if (args.send):
        if (len(args.files) > 0):
            connect: Callable[[SFTPSender], bool]
            if (isIP(args.host)):
                if (not args.port):
                    raise Exception('No port specified')
                connect = lambda sender: sender.connect(args.host, args.port, args.timeout)
            else:
                connect = lambda sender: sender.connectFriendly(args.host, args.timeout)
            sender = SFTPSender()
            if (connect(sender)):
                for file in args.files:
                    sender.sendFile(file, args.timeout)
            else:
                sender.close()
                raise Exception('Unable to connect')
            sender.close()
        else:
            raise Exception('No file specified')
    elif (args.receive):
        args.files = CustomList(args.files)
        if (not args.port):
            args.port = 0
        if (args.accept == 1):
            receiver = SFTPReceiver(args.port)
            if (args.count == 1):
                if (args.name):
                    if (args.zipfile):
                        receiver.receiveFriendlyZip(args.name, args.files.popper(0), args.timeout)
                    else:
                        receiver.receiveFriendly(args.name, args.files.popper(0), args.timeout)
                else:
                    if (args.zipfile):
                        receiver.receiveZip(args.files.popper(0), args.timeout)
                    else:
                        receiver.receive(args.files.popper(0), args.timeout)
            else:
                if (args.name):
                    receiver.receiveMultipleFriendly(args.name, args.count, args.files, args.timeout)
                else:
                    receiver.receiveMultiple(args.count, args.files, args.timeout)
            receiver.close()
        else:
            receiver = ThreadingSFTPReceiver(args.port)
            if (args.count == 1):
                if (args.name):
                    receiver.treceiveFriendly(args.name, args.accept, args.files.popper(0), args.timeout)
                else:
                    receiver.treceive(args.accept, args.files.popper(0), args.timeout)
            else:
                if (args.name):
                    receiver.treceiveMultipleFriendly(args.name, args.accept, args.count, args.files, args.timeout)
                else:
                    receiver.treceiveMultiple(args.accept, args.count, args.files, args.timeout)
            receiver.close()
    else:
        raise Exception('Unknown mode')

if __name__ == '__main__':
    main()
