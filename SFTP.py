from __future__ import annotations

import argparse
from enum import IntEnum, StrEnum
import hashlib
import hmac
import json
import os
import sys
import time
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import struct
import tarfile
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import (
    Any,
    BinaryIO,
    Dict,
    Iterable,
    Iterator,
    NamedTuple,
    Self,
    Union,
)
from types import TracebackType

MAGIC = b"SFTP"
PROTOCOL_VERSION = 1
MAX_FRAME_SIZE = 1024 * 1024
CHUNK_SIZE = 64 * 1024
MAX_ARCHIVE_MEMBERS = 100_000
MAX_ARCHIVE_SIZE = 1 << 40
DISCOVERY_MAX_PACKET_SIZE = 4096
MULTICAST_GROUP = "239.255.255.250"
DISCOVERY_PORT = 12000


Schema = Dict[str, Union["Schema", type]]


class MessageType(IntEnum):
    HELLO = 1
    AUTH_CHALLENGE = 2
    AUTH_RESPONSE = 3
    TRANSFER_METADATA = 4
    ACCEPT = 5
    REJECT = 6
    ARCHIVE_CHUNK = 7
    ARCHIVE_END = 8
    TRANSFER_RESULT = 9


class DiscoveryType(StrEnum):
    DISCOVER = "discover"
    RESPONSE = "response"


class DiscoveryRole(StrEnum):
    SENDER = "sender"
    RECEIVER = "receiver"


class TransportMode(StrEnum):
    RAW = "raw"
    CERTIFICATE = "certificate"
    PSK = "psk"


class ProtocolError(Exception):
    pass


class JSONSchemaError(Exception):
    pass


class Address(NamedTuple):
    host: str
    port: int


def string_to_bytes(s: str) -> bytes:
    return s.encode(encoding="utf-8", errors="strict")


def bytes_to_string(b: bytes) -> str:
    return b.decode(encoding="utf-8", errors="strict")


def json_encode(obj: Any) -> bytes:
    return string_to_bytes(json.dumps(obj, separators=(",", ":")))


def json_verify_schema(obj: Any, schema: Schema) -> Any:
    for k, v in schema.items():
        if isinstance(v, type):
            if not isinstance(obj[k], v):
                raise JSONSchemaError(f'invalid JSON schema for "{k}"')
        else:
            try:
                return json_verify_schema(obj[k], v)
            except JSONSchemaError as exc:
                raise JSONSchemaError(f'invalid JSON schema for "{k}"') from exc
    return obj


def json_decode(s: str | bytes | bytearray) -> Any:
    try:
        return json.loads(s)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("invalid JSON payload") from exc


def json_decode_schema(s: str | bytes | bytearray, schema: Schema) -> Any:
    value = json_decode(s)
    try:
        return json_verify_schema(value, schema)
    except JSONSchemaError as exc:
        raise ProtocolError("invalid JSON schema") from exc


def progress[T](iterable: Iterable[T], update_interval: float = 0.5) -> Iterator[T]:
    start = last_update = time.monotonic()

    for i, item in enumerate(iterable, 1):
        yield item

        now = time.monotonic()
        elapsed = now - start

        if (now - last_update) > update_interval:
            rate = i / elapsed if elapsed else 0

            print(
                f"\rProcessed: {i:,} | "
                f"Elapsed: {elapsed:.1f}s | "
                f"Rate: {rate:,.1f}/s",
                end="",
                file=sys.stderr,
            )

            last_update = now

    print(file=sys.stderr)


def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("connection closed")
        data.extend(chunk)
    return bytes(data)


def send_frame(sock: socket.socket, message_type: int, payload: bytes) -> None:
    if len(payload) > MAX_FRAME_SIZE:
        raise ProtocolError("frame is too large")
    version_type = bytes([PROTOCOL_VERSION, message_type])
    length = struct.pack("!I", len(payload))
    sock.sendall(MAGIC + version_type + length + payload)


def decode_message_type(data: int) -> MessageType:
    try:
        return MessageType(data)
    except ValueError as exc:
        raise ProtocolError("unknown message type") from exc


def decode_discovery_type(data: str) -> DiscoveryType:
    try:
        return DiscoveryType(data)
    except ValueError as exc:
        raise ProtocolError("unknown discovery type") from exc


def decode_discovery_role(data: str) -> DiscoveryRole:
    try:
        return DiscoveryRole(data)
    except ValueError as exc:
        raise ProtocolError("unknown discovery role") from exc


def decode_transport_mode(data: str) -> TransportMode:
    try:
        return TransportMode(data)
    except ValueError as exc:
        raise ProtocolError("unknown transport mode") from exc


def recv_frame(sock: socket.socket) -> tuple[int, bytes]:
    header = recv_exact(sock, 10)
    if header[:4] != MAGIC:
        raise ProtocolError("invalid protocol header magic")
    if header[4] != PROTOCOL_VERSION:
        raise ProtocolError("invalid protocol header version")
    message_type = decode_message_type(header[5])
    size = struct.unpack("!I", header[6:10])[0]
    if size > MAX_FRAME_SIZE:
        raise ProtocolError("frame is too large")
    return message_type, recv_exact(sock, size)


def send_json(sock: socket.socket, message_type: int, value: Any) -> None:
    payload = json_encode(value)
    send_frame(sock, message_type, payload)


def recv_json(sock: socket.socket) -> tuple[int, Any]:
    message_type, payload = recv_frame(sock)
    value = json_decode(payload)
    return message_type, value


def encode_discovery(
    name: str,
    port: int,
    transport: TransportMode,
    type: DiscoveryType,
    role: DiscoveryRole,
) -> bytes:
    value = {
        "version": PROTOCOL_VERSION,
        "type": type.value,
        "name": name,
        "port": port,
        "transport": transport.value,
        "role": role.value,
    }
    payload = json_encode(value)
    return MAGIC + payload


def decode_discovery(packet: bytes) -> tuple[str, int, TransportMode, DiscoveryRole]:
    if not packet.startswith(MAGIC):
        raise ProtocolError("invalid discovery packet")
    payload = packet[len(MAGIC) :]
    schema = {
        "version": int,
        "type": str,
        "name": str,
        "port": int,
        "transport": str,
        "role": str,
    }
    value = json_decode_schema(payload, schema)
    if value["version"] != PROTOCOL_VERSION:
        raise ProtocolError("invalid discovery response protocol version")
    discovery_type = decode_discovery_type(value["type"])
    if discovery_type != DiscoveryType.RESPONSE:
        raise ProtocolError("invalid discovery response type")
    name = value["name"]
    port = value["port"]
    transport = decode_transport_mode(value["transport"])
    discovery_role = decode_discovery_role(value["role"])
    if not 1 <= port <= 65535:
        raise ProtocolError("invalid discovery port range")
    return name, port, transport, discovery_role


class DummyService:
    def __init__(self):
        pass

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        return None


class DiscoveryService:
    def __init__(
        self, name: str, port: int, transport: TransportMode, role: DiscoveryRole
    ):
        self._name = name
        self._port = port
        self._transport = transport
        self._role = role
        self._stop = threading.Event()
        #
        self._sock = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP
        )
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        group = socket.inet_aton(MULTICAST_GROUP)
        mreq = struct.pack("4s4s", group, socket.inet_aton("0.0.0.0"))
        self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        self._sock.bind(("", DISCOVERY_PORT))
        self._sock.settimeout(0.2)
        #
        self._thread = threading.Thread(target=self._thread_fn, daemon=True)
        self._thread.start()

    def _thread_fn(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                packet, address = self._sock.recvfrom(DISCOVERY_MAX_PACKET_SIZE)
                if not packet.startswith(MAGIC):
                    continue
                payload = packet[len(MAGIC) :]
                schema = {
                    "version": int,
                    "type": str,
                    "name": str,
                    "transport": str,
                    "role": str,
                }
                value = json_decode_schema(payload, schema)
                if value["version"] != PROTOCOL_VERSION:
                    continue
                discovery_type = decode_discovery_type(value["type"])
                if discovery_type != DiscoveryType.DISCOVER:
                    continue
                if value["name"] != self._name:
                    continue
                discovery_role = decode_discovery_role(value["role"])
                transport = decode_transport_mode(value["transport"])
                if transport != self._transport or discovery_role != self._role:
                    continue
                data = encode_discovery(
                    self._name,
                    self._port,
                    self._transport,
                    type=DiscoveryType.RESPONSE,
                    role=self._role,
                )
                self._sock.sendto(data, address)
            except (OSError, ProtocolError):
                continue

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            self._sock.close()
        if self._thread:
            self._thread.join()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        self.stop()
        return None

    @staticmethod
    def find(
        name: str,
        transport: TransportMode,
        role: DiscoveryRole,
        timeout: float = 3.0,
    ) -> Address | None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(timeout)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            data = encode_discovery(
                name,
                port=0,
                transport=transport,
                type=DiscoveryType.DISCOVER,
                role=role,
            )
            sock.sendto(data, (MULTICAST_GROUP, DISCOVERY_PORT))
            while True:
                packet, address = sock.recvfrom(DISCOVERY_MAX_PACKET_SIZE)
                response_name, port, response_transport, response_role = (
                    decode_discovery(packet)
                )
                if (
                    response_name == name
                    and response_transport == transport
                    and response_role == role
                ):
                    return Address(address[0], port)
        except (socket.timeout, ProtocolError):
            return None
        finally:
            sock.close()


def maybe_discovery_service(
    name: str | None, port: int, transport: TransportMode, role: DiscoveryRole
):
    if name is None:
        return DummyService()
    return DiscoveryService(name, port, transport, role)


def iter_archive(sources: Iterable[Path], compressed: bool) -> Iterator[bytes]:
    read_fd, write_fd = os.pipe()

    reader = os.fdopen(read_fd, "rb")
    writer = os.fdopen(write_fd, "wb", buffering=0)

    def build() -> None:
        try:
            mode = "w|gz" if compressed else "w|"
            with tarfile.open(fileobj=writer, mode=mode) as archive:
                for source in sources:
                    archive.add(source, arcname=source.name)
        finally:
            writer.close()

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(build)
        try:
            while chunk := reader.read(CHUNK_SIZE):
                yield chunk
            future.result()
        finally:
            reader.close()


class _ArchiveReader(BinaryIO):
    def __init__(self, chunks: Iterable[bytes]):
        self._chunks = iter(chunks)
        self._buffer = bytearray()
        self._done = False

    def read(self, size: int = -1) -> bytes:
        while not self._done and (size < 0 or len(self._buffer) < size):
            try:
                self._buffer.extend(next(self._chunks))
            except StopIteration:
                self._done = True
        if size < 0:
            result = bytes(self._buffer)
            self._buffer = bytearray()
        else:
            result = bytes(self._buffer[:size])
            del self._buffer[:size]
        return result


def validate_member(member: tarfile.TarInfo, staging: Path, seen: set[str]) -> None:
    relative = Path(member.name)
    if relative.is_absolute() or ".." in relative.parts:
        raise ProtocolError("archive path escapes destination")
    key = relative.as_posix()
    if key in seen:
        raise ProtocolError("duplicate archive path")
    seen.add(key)
    if member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
        raise ProtocolError("unsupported archive member")
    target = (staging / relative).resolve()
    if os.path.commonpath((str(staging.resolve()), str(target))) != str(
        staging.resolve()
    ):
        raise ProtocolError("archive path escapes destination")


def extract_archive(chunks: Iterable[bytes], staging: Path, compressed: bool) -> None:
    staging.mkdir(parents=True, exist_ok=True)
    mode = "r|gz" if compressed else "r|"
    seen: set[str] = set()
    total_size = 0
    with tarfile.open(fileobj=_ArchiveReader(chunks), mode=mode) as archive:
        for member in archive:
            if member.size < 0:
                raise ProtocolError("archive invalid member size")
            total_size += member.size
            if total_size > MAX_ARCHIVE_SIZE:
                raise ProtocolError("archive exceeds size limit")
            validate_member(member, staging, seen)
            if len(seen) >= MAX_ARCHIVE_MEMBERS:
                raise ProtocolError("archive exceeds member limits")
            target = staging / member.name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise ProtocolError("missing archive file data")
                with source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)


def _transport_mode(
    certfile: str | None, keyfile: str | None, psk: str | None
) -> TransportMode:
    if bool(certfile) != bool(keyfile):
        raise ValueError("certificate and key must be provided together")
    if certfile and psk:
        raise ValueError("certificate TLS and PSK TLS are mutually exclusive")
    if psk == "":
        raise ValueError("PSK must not be empty")
    if certfile:
        return TransportMode.CERTIFICATE
    if psk:
        return TransportMode.PSK
    return TransportMode.RAW


def _client_transport(
    certfile: str | None,
    keyfile: str | None,
    cafile: str | None,
    psk: str | None,
) -> TransportMode:
    if bool(certfile) != bool(keyfile) or bool(certfile) != bool(cafile):
        raise ValueError("certificate, key, and CA file must be provided together")
    if cafile and psk:
        raise ValueError("certificate TLS and PSK TLS are mutually exclusive")
    if certfile:
        return TransportMode.CERTIFICATE
    if psk:
        return TransportMode.PSK
    return TransportMode.RAW


def _require_psk() -> None:
    if not getattr(ssl, "HAS_PSK", False) or not all(
        hasattr(ssl.SSLContext, name)
        for name in ("set_psk_client_callback", "set_psk_server_callback")
    ):
        raise RuntimeError("TLS-PSK requires Python 3.13+ with OpenSSL PSK support")


def _tls_psk_server(
    sock: socket.socket, psk: str, identity: str = "sftp"
) -> socket.socket:
    _require_psk()
    if not psk:
        raise ValueError("PSK must not be empty")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.set_psk_server_callback(
        lambda client_identity: string_to_bytes(psk), identity
    )
    return context.wrap_socket(sock, server_side=True)


def _tls_psk_client(
    sock: socket.socket, psk: str, identity: str = "sftp"
) -> socket.socket:
    _require_psk()
    if not psk:
        raise ValueError("PSK must not be empty")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_psk_client_callback(lambda hint: (identity, string_to_bytes(psk)))
    return context.wrap_socket(sock, server_hostname=None)


def _tls_server(
    sock: socket.socket, certfile: str, keyfile: str, cafile: str
) -> socket.socket:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile, keyfile)
    context.load_verify_locations(cafile)
    context.verify_mode = ssl.CERT_REQUIRED
    return context.wrap_socket(sock, server_side=True)


def _tls_client(
    sock: socket.socket, certfile: str, keyfile: str, cafile: str
) -> socket.socket:
    context = ssl.create_default_context(cafile=cafile)
    context.load_cert_chain(certfile, keyfile)
    return context.wrap_socket(sock, server_hostname="sftp")


def _staging_path(destination: Path) -> Path:
    return Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.", dir=destination.parent)
    )


def _commit(staging: Path, destination: Path, overwrite: bool) -> None:
    if destination.exists() and not overwrite:
        raise FileExistsError(destination)
    if destination.exists():
        if destination.is_dir():
            shutil.rmtree(destination)
        else:
            destination.unlink()
    os.replace(staging, destination)


def _send_transfer(
    sock: socket.socket,
    sources: list[Path],
    format: str,
    transport: TransportMode,
    token: str | None,
) -> None:
    send_json(sock, MessageType.HELLO, {"transport": transport.value})
    message, value = recv_json(sock)
    if message == MessageType.AUTH_CHALLENGE:
        if token is None:
            raise ProtocolError("receiver requires a token")
        json_verify_schema(value, {"nonce": str})
        response = hmac.new(
            key=string_to_bytes(token),
            msg=string_to_bytes(value["nonce"]),
            digestmod=hashlib.sha256,
        ).hexdigest()
        send_json(sock, MessageType.AUTH_RESPONSE, {"response": response})
        message, value = recv_json(sock)
    if message != MessageType.ACCEPT:
        raise ProtocolError(value.get("error", "connection rejected"))
    compressed = format == "tar.gz"
    send_json(
        sock,
        MessageType.TRANSFER_METADATA,
        {"format": format, "source_count": len(sources)},
    )
    message, value = recv_json(sock)
    if message != MessageType.ACCEPT:
        raise ProtocolError(value.get("error", "transfer rejected"))
    for chunk in progress(iter_archive(sources, compressed)):
        send_frame(sock, MessageType.ARCHIVE_CHUNK, chunk)
    send_frame(sock, MessageType.ARCHIVE_END, b"")
    message, value = recv_json(sock)
    if message != MessageType.TRANSFER_RESULT or value.get("ok") is None:
        raise ProtocolError(value.get("error", "transfer failed"))


def _archive_chunks(connection: socket.socket) -> Iterator[bytes]:
    while True:
        message, payload = recv_frame(connection)
        if message == MessageType.ARCHIVE_END:
            return
        if message != MessageType.ARCHIVE_CHUNK:
            raise ProtocolError("expected archive chunk")
        yield payload


def _receive_transfer(
    connection: socket.socket,
    destination: Path,
    overwrite: bool,
    transport: TransportMode,
    token: str | None,
) -> None:
    try:
        message, value = recv_json(connection)
        if message != MessageType.HELLO or value.get("transport") != transport.value:
            send_json(
                connection, MessageType.REJECT, {"error": "security mode mismatch"}
            )
            return
        if token:
            nonce = secrets.token_hex(24)
            send_json(connection, MessageType.AUTH_CHALLENGE, {"nonce": nonce})
            message, value = recv_json(connection)
            expected = hmac.new(
                key=string_to_bytes(token),
                msg=string_to_bytes(nonce),
                digestmod=hashlib.sha256,
            ).hexdigest()
            if message != MessageType.AUTH_RESPONSE or not hmac.compare_digest(
                value.get("response", ""), expected
            ):
                send_json(
                    connection,
                    MessageType.REJECT,
                    {"error": "authentication failed"},
                )
                return
        send_json(connection, MessageType.ACCEPT, {})
        message, value = recv_json(connection)
        if message != MessageType.TRANSFER_METADATA or value.get("format") not in (
            "tar",
            "tar.gz",
        ):
            send_json(
                connection, MessageType.REJECT, {"error": "invalid transfer metadata"}
            )
            return
        compressed = value["format"] == "tar.gz"
        if destination.exists() and not overwrite:
            send_json(connection, MessageType.REJECT, {"error": "destination exists"})
            return
        send_json(connection, MessageType.ACCEPT, {})
        staging = _staging_path(destination)
        try:
            extract_archive(progress(_archive_chunks(connection)), staging, compressed)
            _commit(staging, destination, overwrite)
        except BaseException as exc:
            shutil.rmtree(staging, ignore_errors=True)
            raise exc
        send_json(connection, MessageType.TRANSFER_RESULT, {"ok": True})
    except BaseException as exc:
        try:
            send_json(
                connection,
                MessageType.TRANSFER_RESULT,
                {"ok": False, "error": str(exc)},
            )
        except OSError:
            pass
        raise


class TransferClient:
    def __init__(
        self,
        token: str | None = None,
        psk: str | None = None,
        cafile: str | None = None,
        certfile: str | None = None,
        keyfile: str | None = None,
    ):
        self._token = token
        self._psk = psk
        self._cafile = cafile
        self._certfile = certfile
        self._keyfile = keyfile
        self._transport = _client_transport(certfile, keyfile, cafile, psk)

    def connect(
        self, host: str, port: int, timeout: float | None = None
    ) -> socket.socket:
        sock = socket.create_connection((host, port), timeout)
        if self._transport == TransportMode.CERTIFICATE:
            if self._certfile is None:
                raise RuntimeError("certfile required for secure transport")
            if self._keyfile is None:
                raise RuntimeError("keyfile required for secure transport")
            if self._cafile is None:
                raise RuntimeError("cafile required for secure transport")
            return _tls_client(sock, self._certfile, self._keyfile, self._cafile)
        if self._transport == TransportMode.PSK:
            if self._psk is None:
                raise RuntimeError("psk required for secure transport")
            return _tls_psk_client(sock, self._psk)
        return sock

    def send(
        self,
        sources: list[Path],
        format: str,
        host: str,
        port: int,
        timeout: float | None = None,
    ) -> None:
        sock = self.connect(host, port, timeout)
        try:
            _send_transfer(sock, sources, format, self._transport, self._token)
        finally:
            sock.close()

    def receive(
        self,
        host: str,
        port: int,
        destination: Path,
        overwrite: bool = False,
        timeout: float | None = None,
    ) -> None:
        sock = self.connect(host, port, timeout)
        try:
            _receive_transfer(
                sock, destination, overwrite, self._transport, self._token
            )
        finally:
            sock.close()


class TransferServer:
    def __init__(
        self,
        port: int = 0,
        token: str | None = None,
        psk: str | None = None,
        cafile: str | None = None,
        certfile: str | None = None,
        keyfile: str | None = None,
    ):
        self._token = token
        self._psk = psk
        self._cafile = cafile
        self._certfile = certfile
        self._keyfile = keyfile
        self._transport = _transport_mode(certfile, keyfile, psk)
        #
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("", port))
        self._sock.listen(1)

    @property
    def port(self) -> int:
        return self._sock.getsockname()[1]

    @property
    def transport(self) -> TransportMode:
        return self._transport

    def _accept_connection(self, timeout: float | None):
        self._sock.settimeout(timeout)
        connection, _ = self._sock.accept()
        if self._transport == TransportMode.CERTIFICATE:
            if self._certfile is None:
                raise RuntimeError("certfile required for secure transport")
            if self._keyfile is None:
                raise RuntimeError("keyfile required for secure transport")
            if self._cafile is None:
                raise RuntimeError("cafile required for secure transport")
            connection = _tls_server(
                connection, self._certfile, self._keyfile, self._cafile
            )
        elif self._transport == TransportMode.PSK:
            if self._psk is None:
                raise RuntimeError("psk required for secure transport")
            connection = _tls_psk_server(connection, self._psk)
        return connection

    def accept_once(
        self, destination: Path, overwrite: bool = False, timeout: float | None = None
    ) -> None:
        connection = self._accept_connection(timeout)
        try:
            _receive_transfer(
                connection, destination, overwrite, self._transport, self._token
            )
        finally:
            connection.close()

    def send_once(
        self, sources: list[Path], format: str, timeout: float | None = None
    ) -> None:
        connection = self._accept_connection(timeout)
        try:
            _send_transfer(connection, sources, format, self._transport, self._token)
        finally:
            connection.close()

    def close(self) -> None:
        self._sock.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        self.close()
        return None


def send_command(args: argparse.Namespace) -> int:
    if args.reverse:
        server = TransferServer(
            args.port or 0,
            args.token,
            args.psk,
            args.cafile,
            args.certfile,
            args.keyfile,
        )
        discovery = maybe_discovery_service(
            args.name, server.port, server.transport, DiscoveryRole.SENDER
        )
        with server, discovery:
            server.send_once(
                [Path(source) for source in args.sources], args.format, args.timeout
            )
        return 0
    if args.host and args.port:
        address = Address(args.host, args.port)
    elif args.name:
        address = DiscoveryService.find(
            args.name,
            _client_transport(args.certfile, args.keyfile, args.cafile, args.psk),
            DiscoveryRole.RECEIVER,
            args.timeout,
        )
        if address is None:
            raise RuntimeError("unable to resolve the provided name")
    else:
        raise RuntimeError("host/port or discoverable name is required")
    TransferClient(args.token, args.psk, args.cafile, args.certfile, args.keyfile).send(
        [Path(source) for source in args.sources],
        args.format,
        address.host,
        address.port,
        args.timeout,
    )
    return 0


def receive_command(args: argparse.Namespace) -> int:
    if args.reverse:
        if args.host and args.port:
            address = Address(args.host, args.port)
        elif args.name:
            address = DiscoveryService.find(
                args.name,
                _client_transport(args.certfile, args.keyfile, args.cafile, args.psk),
                DiscoveryRole.SENDER,
                args.timeout,
            )
            if address is None:
                raise RuntimeError("unable to resolve the provided name")
        else:
            raise RuntimeError("host/port or discoverable name is required")
        TransferClient(
            args.token, args.psk, args.cafile, args.certfile, args.keyfile
        ).receive(
            address.host,
            address.port,
            args.destination,
            args.overwrite,
            args.timeout,
        )
        return 0
    server = TransferServer(
        args.port,
        args.token,
        args.psk,
        args.cafile,
        args.certfile,
        args.keyfile,
    )
    discovery = maybe_discovery_service(
        args.name, server.port, server.transport, DiscoveryRole.RECEIVER
    )
    with server, discovery:
        server.accept_once(args.destination, args.overwrite, args.timeout)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Transfer files and directories between one sender and one receiver.",
        epilog="Use --help with send or receive for mode-specific options.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        allow_abbrev=False,
    )
    subparsers = parser.add_subparsers(required=True, title="commands")
    send = subparsers.add_parser(
        "send",
        aliases=["s"],
        help="Send files or directories.",
        description="Send one or more files or directories.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        allow_abbrev=False,
    )
    send.add_argument("--name", help="Receiver service name for multicast discovery.")
    send.add_argument("--host", help="Receiver hostname or IP address.")
    send.add_argument("--port", type=int, help="Receiver TCP port.")
    send.add_argument("--token", help="Pairing token for application authentication.")
    send.add_argument("--psk", help="TLS-PSK secret; enables encrypted transport.")
    send.add_argument("--cafile", help="CA certificate file used to verify the peer.")
    send.add_argument("--certfile", help="Local TLS certificate file.")
    send.add_argument("--keyfile", help="Local TLS private key file.")
    send.add_argument(
        "--reverse",
        action="store_true",
        help="Listen for the receiver instead of connecting to it.",
    )
    send.add_argument(
        "--format", choices=("tar", "tar.gz"), default="tar", help="Archive format."
    )
    send.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="Connection and discovery timeout in seconds.",
    )
    send.add_argument("sources", nargs="+", help="Files or directories to send.")
    send.set_defaults(function=send_command)
    receive = subparsers.add_parser(
        "receive",
        aliases=["r"],
        help="Receive files or directories.",
        description="Receive one archive into a destination path.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        allow_abbrev=False,
    )
    receive.add_argument(
        "--name", help="Service name to advertise for multicast discovery."
    )
    receive.add_argument(
        "--host", help="Sender hostname or IP address in reverse mode."
    )
    receive.add_argument(
        "--port",
        type=int,
        default=0,
        help="TCP port to listen on; 0 selects a free port.",
    )
    receive.add_argument(
        "--token", help="Pairing token required from the sender, with or without TLS."
    )
    receive.add_argument("--psk", help="TLS-PSK secret; enables encrypted transport.")
    receive.add_argument(
        "--cafile", help="CA certificate file used to verify the peer."
    )
    receive.add_argument("--certfile", help="Local TLS certificate file.")
    receive.add_argument("--keyfile", help="Local TLS private key file.")
    receive.add_argument(
        "--reverse",
        action="store_true",
        help="Connect to a listening sender instead of waiting for one.",
    )
    receive.add_argument(
        "--overwrite", action="store_true", help="Replace an existing destination."
    )
    receive.add_argument(
        "--timeout", type=float, default=None, help="Wait timeout in seconds."
    )
    receive.add_argument("destination", type=Path, help="Destination path to create.")
    receive.set_defaults(function=receive_command)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        return args.function(args)
    except (OSError, ProtocolError, RuntimeError, ValueError) as exc:
        print(f"error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
