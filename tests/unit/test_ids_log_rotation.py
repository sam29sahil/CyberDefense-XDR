"""
Unit and Integration Tests for Network IDS Safe Log Rotation & Bounded Retention
CyberDefense XDR
Tests path traversal safety, FIFO and symlink protection, threshold-based rotation,
streaming gzip compression, archive shifting, retention pruning, thread lifecycle,
and REST API endpoints.
"""

import gzip
import json
import os
import shutil
import stat
import tempfile
import time
import unittest
from unittest.mock import patch, MagicMock

from app import create_app
from app.extensions import db
from app.users.models import User
from app.ids.log_rotator import (
    MANAGED_LOG_FILES,
    PROTECTED_NAMES,
    SURICATA_WRITTEN_LOGS,
    is_safe_ids_path,
    is_xdr_suricata_pid,
    compress_file_gzip,
    shift_and_purge_archives,
    rotate_single_log,
    rotate_ids_logs,
    get_ids_log_metrics,
    start_rotation_thread,
    stop_rotation_thread,
    is_rotation_worker_running,
)


class IDSLogRotationTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config["TESTING"] = True
        cls.app.config["WTF_CSRF_ENABLED"] = False

        with cls.app.app_context():
            user = User.query.filter_by(username="ids_rotator_admin").first()
            if not user:
                user = User(
                    username="ids_rotator_admin",
                    email="ids_rotator_admin@cyberdefense.local",
                    first_name="Rotator",
                    last_name="Admin",
                    role="ADMIN",
                    is_active=True,
                )
                user.set_password("AdminSecurePassword123!")
                db.session.add(user)
                db.session.commit()
            cls.test_user_id = user.id

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="ids_test_logs_")
        self.client = self.app.test_client()
        with self.client.session_transaction() as sess:
            sess["user_id"] = self.test_user_id
            sess["_fresh"] = True

    def tearDown(self):
        stop_rotation_thread()
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # 1. Path Safety & FIFO Protection Tests
    # -------------------------------------------------------------------------
    def test_path_safety_validation(self):
        """Test strict path safety: traversal prevention and protected files."""
        # Safe regular file
        safe_file = os.path.join(self.test_dir, "eve.json")
        with open(safe_file, "w") as f:
            f.write("test")
        self.assertTrue(is_safe_ids_path(safe_file, self.test_dir))

        # Traversal attempts
        self.assertFalse(is_safe_ids_path("../../../etc/passwd", self.test_dir))
        self.assertFalse(is_safe_ids_path(os.path.join(self.test_dir, "..", "secret.txt"), self.test_dir))
        self.assertFalse(is_safe_ids_path("/etc/shadow", self.test_dir))
        self.assertFalse(is_safe_ids_path(self.test_dir, self.test_dir))
        self.assertFalse(is_safe_ids_path(None, self.test_dir))
        self.assertFalse(is_safe_ids_path("", self.test_dir))

        # Directory path rejection
        sub_dir = os.path.join(self.test_dir, "subdir")
        os.makedirs(sub_dir, exist_ok=True)
        self.assertFalse(is_safe_ids_path(sub_dir, self.test_dir))

        # Protected file names
        for prot in PROTECTED_NAMES:
            prot_path = os.path.join(self.test_dir, prot)
            with open(prot_path, "w") as f:
                f.write("test")
            self.assertFalse(is_safe_ids_path(prot_path, self.test_dir))

        # FIFO named pipe protection
        fifo_path = os.path.join(self.test_dir, "suricata_pipe")
        if os.path.exists(fifo_path):
            os.remove(fifo_path)
        try:
            os.mkfifo(fifo_path)
            self.assertFalse(is_safe_ids_path(fifo_path, self.test_dir))
        except (AttributeError, OSError):
            pass

    def test_symlink_rejection(self):
        """Test that symbolic links inside the directory are safely rejected."""
        target_file = os.path.join(self.test_dir, "target.log")
        with open(target_file, "w") as f:
            f.write("data")

        symlink_path = os.path.join(self.test_dir, "link_to_target.log")
        try:
            os.symlink(target_file, symlink_path)
            self.assertFalse(is_safe_ids_path(symlink_path, self.test_dir))
        except (OSError, NotImplementedError):
            pass

    # -------------------------------------------------------------------------
    # 2. Gzip Compression and Archive Management Tests
    # -------------------------------------------------------------------------
    def test_compress_file_gzip(self):
        """Test streaming gzip compression removes source file upon verified write."""
        src_path = os.path.join(self.test_dir, "eve.json.1")
        dst_gz = os.path.join(self.test_dir, "eve.json.1.gz")
        payload = b'{"event_type": "alert", "src_ip": "10.0.0.1"}\n' * 500

        with open(src_path, "wb") as f:
            f.write(payload)

        success = compress_file_gzip(src_path, dst_gz)
        self.assertTrue(success)
        self.assertFalse(os.path.exists(src_path))
        self.assertTrue(os.path.exists(dst_gz))
        self.assertGreater(os.path.getsize(dst_gz), 0)

        # Verify decompressed content matches
        with gzip.open(dst_gz, "rb") as gz_in:
            decompressed = gz_in.read()
        self.assertEqual(decompressed, payload)

    def test_shift_and_purge_archives(self):
        """Test archive shifting (.1.gz -> .2.gz) and retention purging past limit."""
        base_name = os.path.join(self.test_dir, "eve.json")
        retention = 3

        # Create archives 1, 2, 3
        for i in range(1, 4):
            path = f"{base_name}.{i}.gz"
            with gzip.open(path, "wb") as f:
                f.write(f"Archive content {i}".encode())

        purged = shift_and_purge_archives(base_name, retention_files=retention)
        # Archive 3 should have been purged because it reached retention limit
        self.assertEqual(purged, 1)
        self.assertFalse(os.path.exists(f"{base_name}.4.gz"))

        # Archive 1 shifted to 2, Archive 2 shifted to 3
        self.assertTrue(os.path.exists(f"{base_name}.2.gz"))
        self.assertTrue(os.path.exists(f"{base_name}.3.gz"))

    # -------------------------------------------------------------------------
    # 3. Single Log Rotation & Suricata Signal Coordination
    # -------------------------------------------------------------------------
    def test_rotate_single_log_with_mock_pid(self):
        """Test rotating single log atomically shifts files and triggers SIGHUP."""
        log_file = os.path.join(self.test_dir, "eve.json")
        with open(log_file, "w") as f:
            f.write('{"timestamp": "2026-09-09T00:00:00Z"}\n' * 100)

        initial_size = os.path.getsize(log_file)
        self.assertGreater(initial_size, 0)

        mock_pid = 99999
        with patch("app.ids.log_rotator.is_xdr_suricata_pid", return_value=True), \
             patch("os.kill") as mock_kill:
            success, msg = rotate_single_log(
                file_path=log_file,
                base_dir=self.test_dir,
                retention_files=5,
                suricata_pid=mock_pid,
            )

            self.assertTrue(success)
            self.assertIn("Successfully rotated eve.json", msg)
            # Active file moved to .1 and compressed to .1.gz
            self.assertFalse(os.path.exists(log_file))
            self.assertFalse(os.path.exists(f"{log_file}.1"))
            self.assertTrue(os.path.exists(f"{log_file}.1.gz"))

            # SIGHUP sent to Suricata PID
            mock_kill.assert_called_once()
            args, _ = mock_kill.call_args
            self.assertEqual(args[0], mock_pid)
            import signal
            self.assertEqual(args[1], signal.SIGHUP)

    def test_is_xdr_suricata_pid_validation(self):
        """Test Suricata PID validation prevents signaling system or unrelated processes."""
        self.assertFalse(is_xdr_suricata_pid(None))
        self.assertFalse(is_xdr_suricata_pid(0))
        self.assertFalse(is_xdr_suricata_pid(1))  # PID 1 (init/systemd) must never be signaled
        self.assertFalse(is_xdr_suricata_pid(-5))

        # Test non-existent PID
        self.assertFalse(is_xdr_suricata_pid(9999999))

        # Mock /proc/{pid}/cmdline with non-suricata vs suricata
        with patch("os.kill", return_value=None), \
             patch("os.path.exists", return_value=True):
            with patch("builtins.open", unittest.mock.mock_open(read_data=b"python3\x00run.py\x00")):
                self.assertFalse(is_xdr_suricata_pid(1234))
            with patch("builtins.open", unittest.mock.mock_open(read_data=b"suricata\x00-c\x00suricata.yaml\x00")):
                self.assertTrue(is_xdr_suricata_pid(1234))

    # -------------------------------------------------------------------------
    # 4. Batch Rotation Orchestration & Threshold Checking
    # -------------------------------------------------------------------------
    def test_rotate_ids_logs_threshold(self):
        """Test rotate_ids_logs rotates only files meeting size criteria."""
        # eve.json: 2 KB
        eve_path = os.path.join(self.test_dir, "eve.json")
        with open(eve_path, "wb") as f:
            f.write(b"E" * 2048)

        # fast.log: 500 bytes
        fast_path = os.path.join(self.test_dir, "fast.log")
        with open(fast_path, "wb") as f:
            f.write(b"F" * 500)

        # suricata_pipe (protected FIFO)
        pipe_path = os.path.join(self.test_dir, "suricata_pipe")
        with open(pipe_path, "w") as f:
            f.write("pipe_data")

        # Rotate with threshold 1024 bytes (1 KB)
        res = rotate_ids_logs(
            log_dir=self.test_dir,
            max_size_bytes=1024,
            retention_files=5,
            suricata_pid=None,
        )

        # eve.json rotated (2048 >= 1024)
        rotated_files = [r["file"] for r in res["rotated"]]
        self.assertIn("eve.json", rotated_files)
        self.assertFalse(os.path.exists(eve_path))
        self.assertTrue(os.path.exists(f"{eve_path}.1.gz"))

        # fast.log skipped (500 < 1024)
        skipped_files = [s["file"] for s in res["skipped"] if isinstance(s, dict)]
        self.assertIn("fast.log", skipped_files)
        self.assertTrue(os.path.exists(fast_path))

        # suricata_pipe must NOT be rotated or touched
        self.assertTrue(os.path.exists(pipe_path))

    def test_rotate_ids_logs_force_flag(self):
        """Test force=True rotates all managed files regardless of threshold."""
        fast_path = os.path.join(self.test_dir, "fast.log")
        with open(fast_path, "wb") as f:
            f.write(b"Alert message 1\n")

        res = rotate_ids_logs(
            log_dir=self.test_dir,
            max_size_bytes=100 * 1024 * 1024,
            retention_files=5,
            force=True,
        )

        rotated_files = [r["file"] for r in res["rotated"]]
        self.assertIn("fast.log", rotated_files)
        self.assertTrue(os.path.exists(f"{fast_path}.1.gz"))

    # -------------------------------------------------------------------------
    # 5. Metrics Collection Tests
    # -------------------------------------------------------------------------
    def test_get_ids_log_metrics(self):
        """Test get_ids_log_metrics returns accurate sizes, archive counts and inodes."""
        eve_path = os.path.join(self.test_dir, "eve.json")
        with open(eve_path, "wb") as f:
            f.write(b"A" * 1024)

        # Create one compressed archive
        with gzip.open(f"{eve_path}.1.gz", "wb") as f:
            f.write(b"B" * 512)

        metrics = get_ids_log_metrics(log_dir=self.test_dir)
        self.assertEqual(metrics["log_directory"], self.test_dir)
        self.assertEqual(metrics["total_active_bytes"], 1024)
        self.assertGreater(metrics["total_archive_bytes"], 0)
        self.assertEqual(metrics["files"]["eve.json"]["exists"], True)
        self.assertEqual(metrics["files"]["eve.json"]["size_bytes"], 1024)
        self.assertIsNotNone(metrics["files"]["eve.json"]["inode"])
        self.assertEqual(metrics["files"]["eve.json"]["archive_count"], 1)

    # -------------------------------------------------------------------------
    # 6. Rotation Background Thread Lifecycle Tests
    # -------------------------------------------------------------------------
    def test_rotation_thread_lifecycle(self):
        """Test background thread start, idempotency, and clean stop."""
        self.assertFalse(is_rotation_worker_running())
        started = start_rotation_thread(interval_seconds=60)
        self.assertTrue(started)
        self.assertTrue(is_rotation_worker_running())

        # Second call must be idempotent
        started_again = start_rotation_thread(interval_seconds=60)
        self.assertTrue(started_again)
        self.assertTrue(is_rotation_worker_running())

        stopped = stop_rotation_thread(timeout=2.0)
        self.assertTrue(stopped)
        self.assertFalse(is_rotation_worker_running())

    # -------------------------------------------------------------------------
    # 7. REST API Endpoints Tests
    # -------------------------------------------------------------------------
    def test_api_logs_status_endpoint(self):
        """Test GET /network-ids/api/logs/status returns valid json metrics."""
        res = self.client.get("/network-ids/api/logs/status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertIn("log_directory", data)
        self.assertIn("files", data)
        self.assertIn("total_active_mb", data)

    def test_api_logs_rotate_endpoint(self):
        """Test POST /network-ids/api/logs/rotate triggers manual rotation."""
        res = self.client.post("/network-ids/api/logs/rotate", json={"force": False})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertIn("rotated", data.get("result", {}))
        self.assertIn("metrics", data)

    # -------------------------------------------------------------------------
    # 8. EVE Worker Inode Detection & Sensor Status Integration
    # -------------------------------------------------------------------------
    def test_eve_ingestion_reopens_on_inode_change(self):
        """Test that tailer pattern detects inode change across rotation seamlessly."""
        eve_path = os.path.join(self.test_dir, "eve.json")
        with open(eve_path, "w", encoding="utf-8") as f:
            f.write('{"line": 1}\n')

        last_inode = None
        f_in = None
        lines_read = []

        # 1. Read first line
        st = os.stat(eve_path)
        last_inode = st.st_ino
        f_in = open(eve_path, "r", encoding="utf-8")
        lines_read.append(f_in.readline().strip())

        # 2. Rotate file: rename to .1 and create fresh eve.json
        os.rename(eve_path, f"{eve_path}.1")
        with open(eve_path, "w", encoding="utf-8") as f_new:
            f_new.write('{"line": 2}\n')

        # 3. Simulate next iteration of ingestion worker
        st2 = os.stat(eve_path)
        self.assertNotEqual(st2.st_ino, last_inode)
        # Reopen on inode change
        if f_in is None or st2.st_ino != last_inode:
            if f_in:
                f_in.close()
            f_in = open(eve_path, "r", encoding="utf-8")
            last_inode = st2.st_ino

        line2 = f_in.readline().strip()
        lines_read.append(line2)
        f_in.close()

        self.assertEqual(lines_read, ['{"line": 1}', '{"line": 2}'])

    def test_sensor_status_includes_log_metrics(self):
        """Test that get_sensor_status() now includes live logMetrics."""
        from app.ids.services import get_sensor_status
        with self.app.app_context():
            status = get_sensor_status()
            self.assertIn("logMetrics", status)
            self.assertIn("log_directory", status["logMetrics"])
            self.assertIn("total_active_mb", status["logMetrics"])
            self.assertIn("files", status["logMetrics"])

    def test_run_py_disables_reloader(self):
        """Ensure run.py explicitly disables Flask reloader to prevent dual-process worker splitting."""
        run_py_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "run.py"
        )
        with open(run_py_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("use_reloader=False", content)


if __name__ == "__main__":
    unittest.main()


