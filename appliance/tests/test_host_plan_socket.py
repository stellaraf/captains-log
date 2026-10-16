"""Framing uses local socketpairs; Linux peer checks use mocked kernel evidence.

These portable tests do not claim Linux SO_PEERCRED or SELinux qualification.
"""
import json
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from nebulalog_manager.common import Refused
from nebulalog_manager import host_plan_socket as wire
from nebulalog_manager.host_job_storage import canonical

REQUEST = {"schema": 1, "action": "capabilities", "actor": {"subject": "a"*64, "session_id": "b"*64}}
OK = {"schema": 1, "status": "ok", "data": {"control": "read_only", "execution_available": False}}


class SocketTests(unittest.TestCase):
    def pair(self):
        client, server = socket.socketpair()
        self.addCleanup(client.close); self.addCleanup(server.close)
        client.settimeout(1)
        return client, server

    def exchange(self, payload, *, peer=(42, 10001, 10001), frame=True, trailing=b"", service=None):
        client, server = self.pair()
        body = struct.pack("!I", len(payload))+payload if frame else payload
        client.sendall(body+trailing); client.shutdown(socket.SHUT_WR)
        service = service or Mock(handle=Mock(return_value=OK))
        wire.handle_connection(server, service, credentials=lambda _: peer)
        response = b""
        while part := client.recv(65536):response += part
        if not response:return None, service
        self.assertGreaterEqual(len(response), 4)
        size = struct.unpack("!I", response[:4])[0]
        self.assertEqual(len(response), size+4)
        self.assertLessEqual(size, wire.MAX_RESPONSE)
        return json.loads(response[4:]), service

    def test_one_frame_and_eof_dispatch_exact_body_once(self):
        result, service = self.exchange(canonical(REQUEST))
        self.assertEqual(result, OK)
        service.handle.assert_called_once()
        self.assertEqual(service.handle.call_args.args, (REQUEST,))

    def test_rejects_incomplete_oversized_empty_and_trailing_frames(self):
        values = [(b"\0\0", False, b""), (struct.pack("!I", 12)+b"{}", False, b""),
                  (struct.pack("!I", wire.MAX_REQUEST+1), False, b""), (b"", True, b""),
                  (canonical(REQUEST), True, b"x"), (canonical(REQUEST), True, struct.pack("!I", 2)+b"{}")]
        for data, framed, trailing in values:
            with self.subTest(data=data[:30]):
                result, service = self.exchange(data, frame=framed, trailing=trailing)
                self.assertEqual(result["reason"], "invalid_request")
                service.handle.assert_not_called()

    def test_strict_utf8_json_duplicates_numbers_depth(self):
        for body in (b'\xff', b'{"schema":1,"schema":1}', b'{"actor":{"sub":1,"sub":2}}', b'{"v":NaN}',
                     b'{}{}', b'['*30+b'0'+b']'*30, b'\xff\xfe{\x00}\x00'):
            with self.subTest(body=body):
                result, service = self.exchange(body)
                self.assertEqual(result["reason"], "invalid_request")
                service.handle.assert_not_called()

    def test_wrong_kernel_peer_is_refused_without_request_dispatch(self):
        for peer in ((42, 0, 0), (42, 10001, 20002), (42, 10002, 10001), (False, 10001, 10001), {"uid": 10001}):
            with self.subTest(peer=peer):
                result, service = self.exchange(canonical(REQUEST), peer=peer)
                self.assertEqual(result["reason"], "peer_not_authorized")
                service.handle.assert_not_called()

    def test_refused_peer_without_write_eof_does_not_hold_connection_open(self):
        client, server = self.pair()
        client.sendall(struct.pack("!I", 2) + b"{}")
        service = Mock()
        wire.handle_connection(server, service, credentials=lambda _: (42, 0, 0))
        response = b""
        while part := client.recv(65536):
            response += part
        self.assertEqual(json.loads(response[4:])["reason"], "peer_not_authorized")
        service.handle.assert_not_called()

    def test_refusal_drain_is_bounded_even_if_peer_keeps_sending(self):
        connection = Mock()
        connection.recv.side_effect = lambda count: b"x" * count
        service = Mock()
        wire.handle_connection(connection, service, credentials=lambda _: (42, 0, 0))
        self.assertEqual(sum(call.args[0] for call in connection.recv.call_args_list), wire.MAX_REQUEST + 4)
        connection.setblocking.assert_called_once_with(False)
        connection.close.assert_called_once()
        service.handle.assert_not_called()

    def test_linux_peer_credentials_exact_struct_and_platform(self):
        connection = Mock()
        with patch.object(wire.platform, "system", return_value="Linux"), patch.object(wire.socket, "SO_PEERCRED", 17, create=True):
            connection.getsockopt.return_value = struct.pack("3i", 73, 10001, 10001)
            self.assertEqual(wire.peer_credentials(connection), (73, 10001, 10001))
            for data in (b"bad", struct.pack("3i", 73, 0, 0), struct.pack("3i", -1, 10001, 10001)):
                connection.getsockopt.return_value = data
                with self.assertRaises(Refused):wire.peer_credentials(connection)
        with patch.object(wire.platform, "system", return_value="Darwin"):
            with self.assertRaises(Refused):wire.peer_credentials(connection)

    def test_missing_client_eof_obeys_total_deadline(self):
        client, server = self.pair()
        client.sendall(struct.pack("!I", len(canonical(REQUEST)))+canonical(REQUEST))
        service = Mock()
        with patch.object(wire, "REQUEST_SECONDS", 0.03):
            wire.handle_connection(server, service, credentials=lambda _: (42, 10001, 10001))
        self.assertEqual(client.recv(1), b"")
        service.handle.assert_not_called()
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))

    def test_slow_processing_cannot_return_late_success(self):
        def slow(*args, **kwargs):
            import time
            time.sleep(0.2)
            return OK
        with patch.object(wire, "REQUEST_SECONDS", 0.03):
            response, _ = self.exchange(canonical(REQUEST), service=Mock(handle=Mock(side_effect=slow)))
        self.assertIsNone(response)

    def test_oversized_and_exception_responses_never_expose_details(self):
        for service in (Mock(handle=Mock(return_value={"secret": "x"*wire.MAX_RESPONSE})),
                        Mock(handle=Mock(side_effect=RuntimeError("PRIVATE /dev/serial secret")))):
            result, _ = self.exchange(canonical(REQUEST), service=service)
            self.assertEqual(result, {"schema": 1, "status": "unavailable", "reason": "host_unavailable"})

    def test_existing_alarm_is_not_replaced(self):
        with patch.object(wire.signal, "getitimer", return_value=(1, 0)), patch.object(wire.signal, "setitimer") as set_timer:
            with self.assertRaises(Refused):
                with wire.bounded_request(10):pass
            set_timer.assert_not_called()

    def test_protected_ancestry_modes_owner_symlink_and_group(self):
        path = Path("/run/nebulalog-control/plans.sock")
        safe = SimpleNamespace(st_mode=stat.S_IFDIR|0o750, st_uid=0, st_gid=20002)
        def info(item):
            return safe if item == path.parent else SimpleNamespace(st_mode=stat.S_IFDIR|0o755, st_uid=0, st_gid=0)
        with patch.object(Path, "lstat", info), patch.object(Path, "stat", return_value=safe):
            self.assertEqual(wire.verify_directory(path), safe)
            for mode, uid, gid in ((stat.S_IFDIR|0o770, 0, 20002), (stat.S_IFDIR|0o750, 1, 20002),
                                   (stat.S_IFDIR|0o750, 0, 1), (stat.S_IFLNK|0o750, 0, 20002)):
                safe.st_mode, safe.st_uid, safe.st_gid = mode, uid, gid
                with self.assertRaises(Refused):wire.verify_directory(path)
        with self.assertRaises(Refused):wire.verify_directory(Path("relative/plans.sock"))


class BoundSocketTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir="/tmp")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name).resolve(); self.directory.chmod(0o750)
        self.path = self.directory/"plans.sock"
        # Only these portable bind tests substitute local ownership. Separate
        # tests above exercise the production root/group/ancestor predicates.
        for patcher in (patch.object(wire, "ROOT_UID", os.getuid()), patch.object(wire, "SOCKET_GROUP", os.getgid()),
                        patch.object(wire, "require_linux_root"), patch.object(wire, "verify_directory", side_effect=lambda p: p.parent.stat())):
            patcher.start(); self.addCleanup(patcher.stop)

    def test_bind_mode_backlog_and_cleanup_only_own_socket(self):
        server = wire.PlanSocket(Mock(), path=self.path).bind()
        self.addCleanup(server.close)
        info = self.path.lstat()
        self.assertTrue(stat.S_ISSOCK(info.st_mode)); self.assertEqual(stat.S_IMODE(info.st_mode), 0o660)
        self.assertEqual(info.st_gid, os.getgid())
        server.close(); self.assertFalse(self.path.exists())

    def test_existing_file_symlink_or_socket_is_never_adopted(self):
        for kind in ("file", "symlink", "socket"):
            with self.subTest(kind=kind):
                existing = None
                if kind == "file":self.path.write_text("preserve")
                elif kind == "symlink":self.path.symlink_to(self.directory/"absent")
                else:
                    existing = socket.socket(socket.AF_UNIX); existing.bind(str(self.path))
                inode = self.path.lstat().st_ino
                with self.assertRaises(Refused):wire.PlanSocket(Mock(), path=self.path).bind()
                self.assertEqual(self.path.lstat().st_ino, inode)
                if existing:existing.close()
                self.path.unlink()

    def test_cleanup_preserves_replaced_file_and_socket(self):
        for kind in ("file", "socket"):
            server = wire.PlanSocket(Mock(), path=self.path).bind()
            self.path.unlink(); replacement = None
            if kind == "file":self.path.write_text("preserve")
            else:
                replacement = socket.socket(socket.AF_UNIX); replacement.bind(str(self.path))
            inode = self.path.lstat().st_ino
            server.close()
            self.assertEqual(self.path.lstat().st_ino, inode)
            if replacement:replacement.close()
            self.path.unlink()


if __name__ == "__main__":unittest.main()
