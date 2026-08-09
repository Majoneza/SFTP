import socket
import ssl
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from pathlib import Path

from SFTP import (
    DiscoveryType,
    DiscoveryRole,
    DiscoveryService,
    MessageType,
    ProtocolError,
    build_parser,
    decode_discovery,
    encode_discovery,
    extract_archive,
    iter_archive,
    recv_frame,
    receive_command,
    send_command,
    send_frame,
    TransferClient,
    TransferServer,
    TransportMode,
    _client_transport,
    _transport_mode,
    validate_member,
)


class FrameTests(unittest.TestCase):
    def test_message_types_have_stable_wire_values(self):
        self.assertEqual(int(MessageType.HELLO), 1)
        self.assertEqual(int(MessageType.TRANSFER_RESULT), 9)

    def test_round_trip_binary_frame(self):
        left, right = socket.socketpair()
        try:
            send_frame(left, 7, b"payload")
            self.assertEqual(recv_frame(right), (7, b"payload"))
        finally:
            left.close()
            right.close()

    def test_rejects_bad_magic(self):
        left, right = socket.socketpair()
        try:
            right.sendall(b"bad!" + bytes([1, 7]) + struct.pack("!I", 0))
            with self.assertRaises(ProtocolError):
                recv_frame(left)
        finally:
            left.close()
            right.close()


class TransportSecurityTests(unittest.TestCase):
    def test_transport_mode_is_raw_without_credentials(self):
        self.assertEqual(_transport_mode(None, None, None), TransportMode.RAW)

    def test_transport_mode_selects_certificate_tls(self):
        self.assertEqual(
            _transport_mode("server.crt", "server.key", None),
            TransportMode.CERTIFICATE,
        )

    def test_transport_mode_selects_psk_tls(self):
        self.assertEqual(_transport_mode(None, None, "secret"), TransportMode.PSK)

    def test_transport_mode_rejects_mixed_or_partial_credentials(self):
        with self.assertRaises(ValueError):
            _transport_mode("server.crt", None, None)
        with self.assertRaises(ValueError):
            _transport_mode("server.crt", "server.key", "secret")

    def test_certificate_tls_requires_identity_and_trust_on_client(self):
        with self.assertRaises(ValueError):
            _client_transport(None, None, "ca.crt", None)
        with self.assertRaises(ValueError):
            _client_transport("client.crt", "client.key", None, None)


class DiscoveryTests(unittest.TestCase):
    def test_packet_round_trip(self):
        packet = encode_discovery(
            "receiver",
            1234,
            TransportMode.CERTIFICATE,
            DiscoveryType.RESPONSE,
            DiscoveryRole.RECEIVER,
        )
        self.assertEqual(
            decode_discovery(packet),
            ("receiver", 1234, TransportMode.CERTIFICATE, DiscoveryRole.RECEIVER),
        )

    def test_malformed_packet_is_rejected(self):
        with self.assertRaises(ProtocolError):
            decode_discovery(b"invalid")

    def test_packet_round_trip_includes_role(self):
        packet = encode_discovery(
            "sender",
            1234,
            TransportMode.PSK,
            DiscoveryType.RESPONSE,
            DiscoveryRole.SENDER,
        )
        self.assertEqual(
            decode_discovery(packet),
            ("sender", 1234, TransportMode.PSK, DiscoveryRole.SENDER),
        )

    def test_discovery_packet_contains_transport_mode_not_secret(self):
        packet = encode_discovery(
            "laptop",
            9000,
            TransportMode.PSK,
            DiscoveryType.RESPONSE,
            DiscoveryRole.SENDER,
        )
        self.assertIn(b'"transport":"psk"', packet)
        self.assertNotIn(b"secret", packet)

    def test_discovery_service_starts(self):
        service = DiscoveryService(
            "startup-check", 12345, TransportMode.RAW, DiscoveryRole.SENDER
        )
        service.stop()


class ArchiveTests(unittest.TestCase):
    def test_directory_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            source.mkdir()
            (source / "nested").mkdir()
            (source / "nested" / "file.txt").write_text("content")
            staging = Path(directory) / "staged"
            extract_archive(iter_archive([source], compressed=True), staging, compressed=True)
            self.assertEqual((staging / "source" / "nested" / "file.txt").read_text(), "content")

    def test_traversal_is_rejected(self):
        with self.assertRaises(ProtocolError):
            validate_member(tarfile.TarInfo("../escape"), Path("/tmp/staging"), set())

    def test_multiple_sources_share_one_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = root / "first.txt", root / "second.txt"
            first.write_text("one")
            second.write_text("two")
            staging = root / "staged"
            extract_archive(iter_archive([first, second], compressed=False), staging, compressed=False)
            self.assertEqual((staging / "first.txt").read_text(), "one")
            self.assertEqual((staging / "second.txt").read_text(), "two")

    def test_iter_archive_can_close_before_producer_finishes(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "large.bin"
            source.write_bytes(b"x" * (2 * 1024 * 1024))
            script = (
                "from pathlib import Path; import sys; "
                "from SFTP import iter_archive; "
                "archive = iter_archive([Path(sys.argv[1])], False); "
                "next(archive); archive.close()"
            )
            subprocess.run(
                [sys.executable, "-c", script, str(source)],
                check=True,
                timeout=2,
            )


class CliTests(unittest.TestCase):
    def test_parser_help_describes_both_modes(self):
        parser = build_parser()
        help_text = parser.format_help()
        self.assertIn("send", help_text)
        self.assertIn("receive", help_text)
        self.assertIn("Transfer files", help_text)

    def test_parser_accepts_reverse_on_both_commands(self):
        parser = build_parser()
        self.assertTrue(parser.parse_args(["send", "--reverse", "file"]).reverse)
        self.assertTrue(
            parser.parse_args(["receive", "--reverse", "destination"]).reverse
        )

    def test_certificate_and_psk_options_are_exclusive(self):
        parser = build_parser()
        send_args = parser.parse_args(
            [
                "send",
                "--host",
                "127.0.0.1",
                "--port",
                "1",
                "--certfile",
                "client.crt",
                "--keyfile",
                "client.key",
                "--cafile",
                "ca.crt",
                "--psk",
                "secret",
                "file",
            ]
        )
        with self.assertRaises(ValueError):
            send_command(send_args)

        receive_args = parser.parse_args(
            [
                "receive",
                "--certfile",
                "server.crt",
                "--keyfile",
                "server.key",
                "--cafile",
                "ca.crt",
                "--psk",
                "secret",
                "destination",
            ]
        )
        with self.assertRaises(ValueError):
            receive_command(receive_args)


class TransferTests(unittest.TestCase):
    @unittest.skipUnless(getattr(ssl, "HAS_PSK", False), "TLS-PSK unavailable")
    def test_psk_transfer_uses_tls_and_completes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.txt"
            source.write_text("psk")
            destination = root / "received"
            server = TransferServer(psk="secret")
            errors = []

            def receive():
                try:
                    server.accept_once(destination, timeout=5)
                except BaseException as exc:
                    errors.append(exc)

            thread = threading.Thread(target=receive)
            thread.start()
            TransferClient(psk="secret").send(
                [source], "tar", "127.0.0.1", server.port, 5
            )
            thread.join()
            server.close()
            self.assertEqual(errors, [])
            self.assertEqual((destination / "source.txt").read_text(), "psk")

    @unittest.skipUnless(getattr(ssl, "HAS_PSK", False), "TLS-PSK unavailable")
    def test_psk_transfer_rejects_wrong_key(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.txt"
            source.write_text("psk")
            destination = root / "received"
            server = TransferServer(psk="secret")
            errors = []

            def receive():
                try:
                    server.accept_once(destination, timeout=5)
                except BaseException as exc:
                    errors.append(exc)

            thread = threading.Thread(target=receive)
            thread.start()
            with self.assertRaises((OSError, ProtocolError)):
                TransferClient(psk="wrong").send(
                    [source], "tar", "127.0.0.1", server.port, 5
                )
            thread.join()
            server.close()
            self.assertFalse(destination.exists())

    def test_localhost_transfer_commits_staged_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            (source / "file.txt").write_text("hello")
            destination = root / "received"
            server = TransferServer()
            errors = []

            def receive():
                try:
                    server.accept_once(destination, timeout=5)
                except BaseException as exc:
                    errors.append(exc)

            thread = threading.Thread(target=receive)
            thread.start()
            TransferClient().send([source], "tar.gz", "127.0.0.1", server.port, 5)
            thread.join()
            server.close()
            self.assertEqual(errors, [])
            self.assertEqual((destination / "source" / "file.txt").read_text(), "hello")

    def test_reverse_insecure_transfer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.txt"
            source.write_text("reverse")
            destination = root / "received"
            server = TransferServer()
            errors = []

            def send():
                try:
                    server.send_once([source], "tar", timeout=5)
                except BaseException as exc:
                    errors.append(exc)

            thread = threading.Thread(target=send)
            thread.start()
            TransferClient().receive(
                "127.0.0.1", server.port, destination, timeout=5
            )
            thread.join()
            server.close()

            self.assertEqual(errors, [])
            self.assertEqual((destination / "source.txt").read_text(), "reverse")

    def test_insecure_transfer_uses_token_authentication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.txt"
            source.write_text("token")
            destination = root / "received"
            server = TransferServer(token="secret")
            errors = []

            def receive():
                try:
                    server.accept_once(destination, timeout=5)
                except BaseException as exc:
                    errors.append(exc)

            thread = threading.Thread(target=receive)
            thread.start()
            with self.assertRaises(ProtocolError):
                TransferClient(token="wrong").send(
                    [source], "tar", "127.0.0.1", server.port, 5
                )
            thread.join()
            server.close()
            self.assertEqual(errors, [])
            self.assertFalse(destination.exists())

    def test_insecure_transfer_accepts_matching_token(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.txt"
            source.write_text("token")
            destination = root / "received"
            server = TransferServer(token="secret")
            errors = []

            def receive():
                try:
                    server.accept_once(destination, timeout=5)
                except BaseException as exc:
                    errors.append(exc)

            thread = threading.Thread(target=receive)
            thread.start()
            TransferClient(token="secret").send(
                [source], "tar", "127.0.0.1", server.port, 5
            )
            thread.join()
            server.close()
            self.assertEqual(errors, [])
            self.assertEqual((destination / "source.txt").read_text(), "token")

    def test_reverse_send_command_listens_for_receiver(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.txt"
            source.write_text("command reverse")
            destination = root / "received"
            probe = socket.socket()
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
            probe.close()
            errors = []

            def send():
                try:
                    send_command(
                        build_parser().parse_args(
                            ["send", "--reverse", "--port", str(port), str(source)]
                        )
                    )
                except BaseException as exc:
                    errors.append(exc)

            thread = threading.Thread(target=send)
            thread.start()
            for _ in range(100):
                try:
                    TransferClient().receive(
                        "127.0.0.1", port, destination, timeout=0.1
                    )
                    break
                except ConnectionRefusedError:
                    time.sleep(0.01)
            else:
                self.fail("reverse sender did not start listening")
            thread.join()
            self.assertEqual(errors, [])
            self.assertEqual(
                (destination / "source.txt").read_text(), "command reverse"
            )

    def test_reverse_receive_command_connects_to_sender(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.txt"
            source.write_text("command receive")
            destination = root / "received"
            listener = TransferServer()
            errors = []

            def receive():
                try:
                    receive_command(
                        build_parser().parse_args(
                            [
                                "receive",
                                "--reverse",
                                "--host",
                                "127.0.0.1",
                                "--port",
                                str(listener.port),
                                str(destination),
                            ]
                        )
                    )
                except BaseException as exc:
                    errors.append(exc)

            thread = threading.Thread(target=receive)
            thread.start()
            listener.send_once([source], "tar", timeout=5)
            thread.join()
            listener.close()
            self.assertEqual(errors, [])
            self.assertEqual(
                (destination / "source.txt").read_text(), "command receive"
            )


if __name__ == "__main__":
    unittest.main()
