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
from enum import Enum
import socket
import os
import struct
import argparse
import threading
from multiprocessing.pool import ThreadPool
import abc
import shutil
from typing import Final, Generator, List, NamedTuple, TypeVar

SFTP_VERSION: Final = 1
SFTP_BUFFER_SIZE: Final = 8192

T = TypeVar('T')
class CustomList(List[T]):
    def popper(self, __index: int) -> T | None:
        if (len(self) > 0):
            return self.pop(__index)
        return None

class Address(NamedTuple):
    host: str
    port: int

class SSDP:
    class SSDP_TYPE(Enum):
        DISCOVER = 0
        RESPONSE = 1
        BAD_REQUEST = 2
    SSDP_VERSION: Final = 1
    SSDP_MULTICAST: Final = '239.255.255.250'
    SSDP_PORT: Final = 12000
    SSDP_ENCODING: Final = 'UTF-8'
    _sock: socket.socket
    _service_name: bytes
    _service_port: int
    _service_thread: threading.Thread
    _shutdown_event: threading.Event
    def __init__(self, name: str, port: int):
        self._service_name = struct.pack('!16s', name.encode(self.SSDP_ENCODING))
        self._service_port = port
        self._service_thread = threading.Thread(target=self.loop, daemon=True)
        self._shutdown_event = threading.Event()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setblocking(True)
        self._sock.bind(('', self.SSDP_PORT))
        group = socket.inet_aton(self.SSDP_MULTICAST)
        mreq = struct.pack('4sL', group, socket.INADDR_ANY)
        self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    def run(self) -> None:
        try:
            data, addr = self._sock.recvfrom(18)
        except (BlockingIOError, BrokenPipeError, OSError):
            return None
        try:
            version, type, name = struct.unpack('!BB16s', data)
            if (version == self.SSDP_VERSION and type == self.SSDP_TYPE.DISCOVER.value
                    and name == self._service_name):
                response = struct.pack('!BB16sH', self.SSDP_VERSION,
                    self.SSDP_TYPE.RESPONSE.value, self._service_name, self._service_port)
                self._sock.sendto(response, addr)
            else:
                print(f'Request: version: {version}, type: {type}, name: {name}')
        except struct.error:
            response = struct.pack('!BB16sH', self.SSDP_VERSION,
                self.SSDP_TYPE.BAD_REQUEST.value, b'', 0)
            self._sock.sendto(response, addr)
    def loop(self) -> None:
        while (not self._shutdown_event.is_set()):
            self.run()
    def __enter__(self) -> None:
        self.start()
    def __exit__(self, exc_type: str, exc_val: str, exc_tb: str) -> None:
        self.stop()
    def start(self) -> None:
        self._service_thread.start()
    def stop(self) -> None:
        self._shutdown_event.set()
        self._sock.close()
        self._service_thread.join()
    @classmethod
    def find_service(cls, name: str, timeout: float | None = None) -> Address | None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        ttl = struct.pack('b', 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
        sock.connect((cls.SSDP_MULTICAST, cls.SSDP_PORT))
        request = struct.pack('!BB16s', cls.SSDP_VERSION, cls.SSDP_TYPE.DISCOVER.value,
            name.encode(cls.SSDP_ENCODING))
        try:
            sock.sendall(request)
            response, addr = sock.recvfrom(20)
        except socket.timeout:
            sock.close()
            return None
        sock.close()
        try:
            version, type, res_name, res_port = struct.unpack('!BB16sH', response)
        except struct.error:
            return None
        if (version == cls.SSDP_VERSION and type == cls.SSDP_TYPE.RESPONSE.value
                and res_name == request[2:]):
            return Address(addr[0], res_port)
        return None

class SFTP(metaclass=abc.ABCMeta):
    SFTP_VERSION: Final = 1
    SFTP_BUFFER_SIZE: Final = 8192
    _sock: socket.socket
    def __init__(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    def close(self):
        self._sock.close()

class SFTPSender(SFTP):
    def connect(self, host: str, port: int | None, timeout: float | None = None) -> bool:
        addresses = socket.getaddrinfo(host, port, family=socket.AF_INET, proto=socket.IPPROTO_TCP)
        if len(addresses) == 0:
            return False
        self._sock.settimeout(timeout)
        try:
            self._sock.connect(addresses[0][4])
        except socket.timeout:
            return False
        return True
    def connectFriendly(self, name: str, timeout: float | None = None) -> bool:
        address = SSDP.find_service(name, timeout)
        if (address):
            return self.connect(address.host, address.port, timeout)
        return False
    def sendFile(self, filename: str, zip: bool = False, timeout: float | None = None) -> None:
        self._sock.settimeout(timeout)
        # Zip file
        if zip:
            filename = shutil.make_archive(filename, 'zip')
        # Get file
        stat = os.stat(filename)
        file = open(filename, 'rb')
        # Pack the packet
        filename_bytes = os.path.basename(filename).encode('UTF-8')
        header = struct.pack('!BHQ', SFTP_VERSION, len(filename_bytes), stat.st_size)
        # Send header
        self._sock.sendall(header)
        # Send filename
        self._sock.sendall(filename_bytes)
        # Send file
        while file.tell() < stat.st_size:
            self._sock.sendfile(file)
            print(f'\r[{round(file.tell() / stat.st_size * 100, 2)}%]', end='')
        print()
        file.close()

class SFTPReceiver(SFTP):
    def __init__(self, port: int = 0):
        super().__init__()
        self._sock.bind(('', port))
        self._sock.listen()
    def _print(self, message: str = '', end: str | None = '\n') -> None:
        print(message, end=end)
    def _receive_file(self, conn_sock: socket.socket, overrideFilename: str | None = None, unzip: bool = False, timeout: float | None = None) -> str:
        conn_sock.settimeout(timeout)
        # Version, File size, Filename characters count
        data = conn_sock.recv(11)
        version, filename_characters_amount, file_size = struct.unpack('!BHQ', data)
        if (version != SFTP_VERSION):
            raise Exception('Unsupported protocol version')
        # Filename
        filename = conn_sock.recv(filename_characters_amount).decode('UTF-8')
        # Override filename
        if (overrideFilename is not None):
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
        self._print()
        # Close file and socket
        file.close()
        conn_sock.close()
        # Unzip file
        if unzip:
            shutil.unpack_archive(filename, format='zip')
        #
        return filename
    def _receive_multiple_files(self, conn_sock: socket.socket, amount: int, overrideFilenames: List[str] | None = None, unzip: bool = False, timeout: float | None = None) -> None:
        if (overrideFilenames is not None):
            overrideFilenames = CustomList(overrideFilenames)
        else:
            overrideFilenames = CustomList()
        while amount:
            amount -= 1
            filename = overrideFilenames.popper(0)
            self._receive_file(conn_sock, filename, unzip, timeout)
    def _accept_sock(self, timeout: float | None = None) -> socket.socket:
        self._sock.settimeout(timeout)
        self._print(f'Listening on {self._sock.getsockname()[1]}')
        conn_sock, conn_addr = self._sock.accept()
        #self._print(f'Connected: {(socket.gethostbyaddr(conn_addr[0])[0], *conn_addr)}')
        self._print(conn_addr)
        return conn_sock
    def _accept_friendly_sock(self, name: str, timeout: float | None = None) -> socket.socket:
        self._sock.settimeout(timeout)
        port = self._sock.getsockname()[1]
        with SSDP(name, port):
            conn_sock, conn_addr = self._sock.accept()
        #self._print(f'Connected: {(socket.gethostbyaddr(conn_addr[0])[0], *conn_addr)}')
        self._print(conn_addr)
        return conn_sock
    def _accept_multiple_sock(self, accept: int, timeout: float | None = None) -> Generator[socket.socket, None, None]:
        self._sock.settimeout(timeout)
        self._print(f'Listening on {self._sock.getsockname()[1]}')
        while accept:
            accept -= 1
            try:
                conn_sock, conn_addr = self._sock.accept()
            except socket.timeout:
                continue
            #self._print(f'Connected: {(socket.gethostbyaddr(conn_addr[0])[0], *conn_addr)}')
            self._print(conn_addr)
            yield conn_sock
    def _accept_multiple_friendly_sock(self, name: str, accept: int, timeout: float | None = None) -> Generator[socket.socket, None, None]:
        self._sock.settimeout(timeout)
        port = self._sock.getsockname()[1]
        with SSDP(name, port):
            while accept:
                accept -= 1
                try:
                    conn_sock, conn_addr = self._sock.accept()
                except socket.timeout:
                    continue
                #self._print(f'Connected: {(socket.gethostbyaddr(conn_addr[0])[0], *conn_addr)}')
                self._print(conn_addr)
                yield conn_sock
    def receive(self, name: str | None = None, overrideFilename: str | None = None, unzip: bool = False, timeout: float | None = None) -> None:
        if name is not None:
            conn_sock = self._accept_friendly_sock(name, timeout)
        else:
            conn_sock = self._accept_sock(timeout)
        self._receive_file(conn_sock, overrideFilename, unzip, timeout)
    def receiveMultiple(self, amount: int, name: str | None = None, overrideFilenames: List[str] | None = None, unzip: bool = False, timeout: float | None = None) -> None:
        if name is not None:
            conn_sock = self._accept_friendly_sock(name, timeout)
        else:
            conn_sock = self._accept_sock(timeout)
        self._receive_multiple_files(conn_sock, amount, overrideFilenames, unzip, timeout)

class ThreadingSFTPReceiver(SFTPReceiver):
    _print_lock: threading.Lock
    def __init__(self, port: int = 0):
        super().__init__(port)
        self._print_lock = threading.Lock()
    def _print(self, message: str = '', end: str | None = '\n') -> None:
        with self._print_lock:
            super()._print(message, end)
    def treceive(self, accept: int, name: str | None = None, overriderFilename: str | None = None, unzip: bool = False, timeout: float | None = None) -> None:
        if name is not None:
            conn_sock_iterator = self._accept_multiple_friendly_sock(name, accept, timeout)
        else:
            conn_sock_iterator = self._accept_multiple_sock(accept, timeout)
        with ThreadPool(accept) as pool:
            for conn_sock in conn_sock_iterator:
                pool.apply(self._receive_file, args=(conn_sock, overriderFilename, unzip, timeout))
    def treceiveMultiple(self, accept: int, amount: int, name: str | None = None, overrideFilename: List[str] | None = None, unzip: bool = False, timeout: float | None = None) -> None:
        if name is not None:
            conn_sock_iterator = self._accept_multiple_friendly_sock(name, accept, timeout)
        else:
            conn_sock_iterator = self._accept_multiple_sock(accept, timeout)
        with ThreadPool(accept) as pool:
            for conn_sock in conn_sock_iterator:
                pool.apply(self._receive_multiple_files, args=(conn_sock, amount, overrideFilename, unzip, timeout))

def isIP(address: str) -> bool:
    try:
        socket.inet_aton(address)
        return True
    except socket.error:
        return False

def pint(value: str) -> int:
    number = int(value)
    if (number <= 0):
        raise ValueError('Value must be a positive integer')
    return number

def nnint(value: str) -> int:
    number = int(value)
    if (number < 0):
        raise ValueError('Value must be a non-negative integer')
    return number

class SendArguments:
    timeout: int | None
    port: int | None
    host: str | None
    name: str | None
    dir: str
    zipfile: bool
    files: List[str]

def send(args: SendArguments):
    sender = SFTPSender()
    if args.name is not None:
        success = sender.connectFriendly(args.name, args.timeout)
    elif args.host is not None:
        success = sender.connect(args.host, args.port, args.timeout)
    else:
        raise RuntimeError('No name or host specified')
    if not success:
        sender.close()
        raise RuntimeError('Unable to connect')
    for file in args.files:
        sender.sendFile(file, args.zipfile, args.timeout)
    sender.close()

class ReceiveArguments:
    timeout: int | None
    port: int
    name: str | None
    accept: int
    count: int
    dir: str
    unzipfile: bool
    files: List[str]

def receive(args: ReceiveArguments):
    args.files = CustomList(args.files)
    if (args.accept == 1):
        receiver = SFTPReceiver(args.port)
        if (args.count == 1):
            receiver.receive(args.name, args.files.popper(0), args.unzipfile, args.timeout)
        else:
            receiver.receiveMultiple(args.count, args.name, args.files, args.unzipfile, args.timeout)
        receiver.close()
    else:
        receiver = ThreadingSFTPReceiver(args.port)
        if (args.count == 1):
            receiver.treceive(args.accept, args.name, args.files.popper(0), args.unzipfile, args.timeout)
        else:
            receiver.treceiveMultiple(args.accept, args.count, args.name, args.files, args.unzipfile, args.timeout)
        receiver.close()

def main():
    parser = argparse.ArgumentParser(
        description='Simple File Transfer Protocol',
        allow_abbrev=False)
    #
    subparsers = parser.add_subparsers(required=True)
    #
    send_parser = subparsers.add_parser('send',
        aliases=['s'],
        help='Send mode',
        description='Send files via the SFTP',
        conflict_handler='resolve',
        allow_abbrev=False)
    send_parser.add_argument('-t', '--timeout',
        type=nnint,
        dest='timeout',
        help='Timeout in seconds')
    send_parser.add_argument('-p', '--port',
        type=nnint,
        dest='port',
        help='Port of the receiver')
    send_parser.add_argument('-h', '--host',
        type=str,
        dest='host',
        help='Hostname of the receiver')
    send_parser.add_argument('-n', '--name',
        type=str,
        dest='name',
        help='Friendly name of the receiver')
    send_parser.add_argument('-d', '--dir',
        type=str,
        dest='dir',
        default='./',
        help="Root directory(default:'./')")
    send_parser.add_argument('-zf', '--zip-file',
        action='store_true',
        dest='zipfile',
        help='Zip files before sending')
    send_parser.add_argument('files',
        type=str,
        nargs='+',
        help='Name of file(s) to send')
    send_parser.set_defaults(function=send)
    #
    receive_parser = subparsers.add_parser('receive',
        aliases=['r'],
        help='Receive mode',
        description='Receive files via the SFTP',
        allow_abbrev=False)
    receive_parser.add_argument('-t', '--timeout',
        type=nnint,
        dest='timeout',
        help='Timeout in seconds')
    receive_parser.add_argument('-p', '--port',
        type=nnint,
        dest='port',
        default=0,
        help='Port to bind to(default:ANY)')
    receive_parser.add_argument('-n', '--name',
        type=str,
        dest='name',
        help='Friendly name to use')
    receive_parser.add_argument('-a', '--accept',
        type=pint,
        dest='accept',
        default=1,
        help='How many connections to accept(default: 1)')
    # Remove count (automatically detect count)
    receive_parser.add_argument('-c', '--count',
        type=pint,
        dest='count',
        default=1,
        help='How many files to receive(default: 1)')
    receive_parser.add_argument('-d', '--dir',
        type=str,
        dest='dir',
        default='./',
        help="Root directory(default:'./')")
    receive_parser.add_argument('-uzf', '--unzip-file',
        action='store_true',
        dest='unzipfile',
        help='Unzip files before receiving')
    receive_parser.add_argument('files',
        type=str,
        nargs='*',
        help='Override received file(s) name')
    receive_parser.set_defaults(function=receive)
    #
    args = parser.parse_args()
    args.function(args)

if __name__ == '__main__':
    main()
