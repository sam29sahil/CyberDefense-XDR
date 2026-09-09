"""
CyberDefense XDR
Network IDS Safe Log Rotation & Bounded Retention Module
Manages eve.json, fast.log, stats.log, suricata.log, and suricata_stderr.log
using Suricata-native SIGHUP signal coordination, streaming gzip compression,
bounded retention pruning, and strict path/FIFO protection.
"""

import gzip
import logging
import os
import shutil
import signal
import stat
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Managed log files that may be rotated
MANAGED_LOG_FILES = (
    "eve.json",
    "fast.log",
    "stats.log",
    "suricata.log",
    "suricata_stderr.log",
)

# Files written by Suricata daemon that require SIGHUP to reopen
SURICATA_WRITTEN_LOGS = (
    "eve.json",
    "fast.log",
    "stats.log",
    "suricata.log",
)

# Files and FIFOs that must NEVER be rotated, truncated, or removed
PROTECTED_NAMES = {
    "suricata_pipe",
    "test_fifo",
}

# Thread synchronization
_rotation_lock = threading.Lock()
_rotation_thread = None
_rotation_stop_event = threading.Event()


def get_default_ids_log_dir() -> str:
    """Returns absolute path to the XDR IDS log directory: <project_root>/instance/ids."""
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    log_dir = os.path.join(root, "instance", "ids")
    os.makedirs(log_dir, exist_ok=True)
    return log_dir


def is_safe_ids_path(target_path: str, base_dir: Optional[str] = None) -> bool:
    """
    Strict security validation: Ensures target path resides within base_dir,
    is not base_dir itself, is not a named pipe (FIFO), symlink, or protected file.
    Prevents path traversal attacks.
    """
    if not target_path or not isinstance(target_path, str):
        return False

    # Check for symlink before resolving path
    try:
        if os.path.islink(target_path):
            logger.warning(f"[IDS Log Safety] Target is a symbolic link: '{target_path}'")
            return False
    except Exception:
        return False

    base = os.path.realpath(base_dir or get_default_ids_log_dir())
    target = os.path.realpath(target_path)

    # Must reside strictly within base directory
    try:
        if os.path.commonpath([base, target]) != base:
            logger.warning(f"[IDS Log Safety] Path escapes base dir: '{target_path}'")
            return False
    except Exception:
        return False

    if target == base:
        return False

    basename = os.path.basename(target)
    if basename in PROTECTED_NAMES:
        logger.warning(f"[IDS Log Safety] Attempted access to protected file: '{basename}'")
        return False

    # Never touch directories
    if os.path.isdir(target):
        return False

    # Check for FIFOs (named pipes) or symlinks if the file exists
    if os.path.exists(target):
        try:
            st = os.lstat(target)
            if stat.S_ISFIFO(st.st_mode):
                logger.warning(f"[IDS Log Safety] Target is a FIFO pipe: '{basename}'")
                return False
            if stat.S_ISLNK(st.st_mode):
                logger.warning(f"[IDS Log Safety] Target is a symbolic link: '{basename}'")
                return False
        except Exception:
            return False

    return True


def is_xdr_suricata_pid(pid: Optional[int]) -> bool:
    """
    Validates that pid belongs to an active Suricata process managed by this XDR instance.
    Prevents sending signals to systemd or unrelated processes.
    """
    if not pid or not isinstance(pid, int) or pid <= 1:
        return False

    try:
        # Check if process exists and is accessible
        os.kill(pid, 0)
    except (OSError, ProcessLookupError):
        return False

    # Inspect /proc/{pid}/cmdline on Linux for verification
    cmdline_path = f"/proc/{pid}/cmdline"
    if os.path.exists(cmdline_path):
        try:
            with open(cmdline_path, "rb") as f:
                content = f.read().decode("utf-8", errors="ignore").replace("\x00", " ")
            # Verify command line is Suricata
            if "suricata" in content.lower():
                return True
        except Exception:
            pass

    return False


def compress_file_gzip(src_path: str, dst_gz_path: str, chunk_size: int = 1024 * 1024) -> bool:
    """
    Streams file into a gzip archive and removes uncompressed original upon completion.
    Safe streaming prevents high memory usage.
    """
    try:
        with open(src_path, "rb") as f_in:
            with gzip.open(dst_gz_path, "wb", compresslevel=6) as f_out:
                shutil.copyfileobj(f_in, f_out, length=chunk_size)

        # Verify compressed archive exists and has non-zero size before deleting original
        if os.path.exists(dst_gz_path) and os.path.getsize(dst_gz_path) > 0:
            os.remove(src_path)
            return True
        else:
            logger.error(f"[IDS Log Rotation] Compressed archive '{dst_gz_path}' is invalid.")
            return False
    except Exception as e:
        logger.error(f"[IDS Log Rotation] Failed to compress '{src_path}' to '{dst_gz_path}': {e}")
        if os.path.exists(dst_gz_path):
            try:
                os.remove(dst_gz_path)
            except Exception:
                pass
        return False


def shift_and_purge_archives(base_file_path: str, retention_files: int) -> int:
    """
    Shifts existing rotated archives (.N.gz -> .N+1.gz) and removes archives
    exceeding the retention limit. Returns number of purged archives.
    """
    purged_count = 0
    # Process descending from retention_files down to 1
    for idx in range(retention_files + 5, 0, -1):
        gz_path = f"{base_file_path}.{idx}.gz"
        uncompressed_path = f"{base_file_path}.{idx}"

        # Handle existing .gz archive
        if os.path.exists(gz_path):
            if idx >= retention_files:
                try:
                    os.remove(gz_path)
                    purged_count += 1
                    logger.info(f"[IDS Log Retention] Purged expired archive: {os.path.basename(gz_path)}")
                except Exception as e:
                    logger.warning(f"[IDS Log Retention] Error purging {gz_path}: {e}")
            else:
                next_gz = f"{base_file_path}.{idx + 1}.gz"
                try:
                    os.rename(gz_path, next_gz)
                except Exception as e:
                    logger.warning(f"[IDS Log Rotation] Error shifting {gz_path} to {next_gz}: {e}")

        # Handle leftover uncompressed .idx if any was left from interrupted rotation
        if os.path.exists(uncompressed_path):
            if idx >= retention_files:
                try:
                    os.remove(uncompressed_path)
                    purged_count += 1
                except Exception:
                    pass
            else:
                next_uncomp = f"{base_file_path}.{idx + 1}"
                try:
                    os.rename(uncompressed_path, next_uncomp)
                except Exception:
                    pass

    return purged_count


def rotate_single_log(
    file_path: str,
    base_dir: Optional[str] = None,
    retention_files: int = 7,
    suricata_pid: Optional[int] = None,
) -> Tuple[bool, str]:
    """
    Rotates a single log file safely:
    1. Validates path and ensures it is a regular file (never a FIFO or link).
    2. Shifts existing archives (.1.gz -> .2.gz, etc.) and purges expired archives.
    3. Atomically renames active file to .1.
    4. If Suricata writes this log, sends SIGHUP to Suricata PID to create a fresh file.
    5. Compresses .1 to .1.gz in background streaming mode.
    """
    base = base_dir or get_default_ids_log_dir()
    if not is_safe_ids_path(file_path, base):
        return False, f"Path rejected by safety policy: {file_path}"

    if not os.path.exists(file_path):
        return False, f"Log file does not exist: {file_path}"

    if not os.path.isfile(file_path):
        return False, f"Target is not a regular file: {file_path}"

    basename = os.path.basename(file_path)
    if basename in PROTECTED_NAMES:
        return False, f"Cannot rotate protected file: {basename}"

    old_size = os.path.getsize(file_path)
    rot_1 = f"{file_path}.1"
    rot_1_gz = f"{file_path}.1.gz"

    try:
        # Step 1: Shift existing archives
        purged = shift_and_purge_archives(file_path, retention_files=retention_files)

        # Step 2: Atomic rename active log file to .1
        os.rename(file_path, rot_1)
        logger.info(f"[IDS Log Rotation] Atomically moved {basename} ({old_size} bytes) -> {basename}.1")

        # Step 3: Coordinate with Suricata if it's a Suricata log
        if basename in SURICATA_WRITTEN_LOGS and is_xdr_suricata_pid(suricata_pid):
            try:
                os.kill(suricata_pid, signal.SIGHUP)
                logger.info(
                    f"[IDS Log Rotation] Sent SIGHUP to XDR Suricata PID {suricata_pid} to re-open log files."
                )
                # Brief pause for Suricata to re-open fresh file descriptor
                time.sleep(0.05)
            except Exception as sig_err:
                logger.warning(f"[IDS Log Rotation] Failed to signal Suricata PID {suricata_pid}: {sig_err}")

        # Step 4: Stream compress .1 to .1.gz
        compressed = compress_file_gzip(rot_1, rot_1_gz)
        if not compressed:
            logger.warning(f"[IDS Log Rotation] Archive left uncompressed as {basename}.1 due to compression error.")

        msg = (
            f"Successfully rotated {basename} ({old_size / (1024 * 1024):.2f} MB). "
            f"Purged {purged} expired archives."
        )
        logger.info(f"[IDS Log Rotation] {msg}")
        return True, msg

    except Exception as e:
        logger.error(f"[IDS Log Rotation] Unexpected failure rotating {basename}: {e}", exc_info=True)
        # Attempt recovery if .1 exists but original is missing
        if not os.path.exists(file_path) and os.path.exists(rot_1):
            try:
                os.rename(rot_1, file_path)
            except Exception:
                pass
        return False, f"Failed to rotate {basename}: {str(e)}"


def rotate_ids_logs(
    log_dir: Optional[str] = None,
    max_size_bytes: Optional[int] = None,
    retention_files: Optional[int] = None,
    suricata_pid: Optional[int] = None,
    force: bool = False,
) -> Dict[str, Any]:
    """
    Orchestrates inspection and rotation across all managed IDS log files.
    Thread-safe; acquires _rotation_lock before execution.
    Only files exceeding max_size_bytes are rotated (unless force is True).
    """
    base = log_dir or get_default_ids_log_dir()

    # Load configuration values from environment or defaults
    if max_size_bytes is None:
        size_mb = int(os.getenv("IDS_LOG_ROTATION_SIZE_MB", "100"))
        max_size_bytes = size_mb * 1024 * 1024

    if retention_files is None:
        retention_files = int(os.getenv("IDS_LOG_RETENTION_FILES", "7"))

    results = {
        "timestamp": time.time(),
        "log_dir": base,
        "max_size_bytes": max_size_bytes,
        "retention_files": retention_files,
        "force": force,
        "rotated": [],
        "skipped": [],
        "errors": [],
    }

    if not _rotation_lock.acquire(blocking=False):
        logger.warning("[IDS Log Rotation] Rotation already in progress. Skipping duplicate execution.")
        results["skipped"].append("Rotation lock held by concurrent worker")
        return results

    try:
        # If suricata_pid not explicitly passed, look it up from running sensor
        if suricata_pid is None:
            try:
                from app.ids.models import IDSSensor
                from app.ids.services import DEFAULT_SENSOR_ID, _sensor_proc
                if _sensor_proc and _sensor_proc.poll() is None:
                    suricata_pid = _sensor_proc.pid
                else:
                    sensor = IDSSensor.query.filter_by(sensor_id=DEFAULT_SENSOR_ID).first()
                    if sensor and sensor.pid and is_xdr_suricata_pid(sensor.pid):
                        suricata_pid = sensor.pid
            except Exception:
                suricata_pid = None

        for filename in MANAGED_LOG_FILES:
            file_path = os.path.join(base, filename)
            if not os.path.exists(file_path):
                continue

            if not is_safe_ids_path(file_path, base):
                results["skipped"].append(f"{filename} (unsafe path)")
                continue

            try:
                current_size = os.path.getsize(file_path)
            except Exception as e:
                results["errors"].append(f"{filename}: {str(e)}")
                continue

            should_rotate = (force and current_size > 0) or (current_size >= max_size_bytes)
            if should_rotate:
                logger.info(
                    f"[IDS Log Rotation] {filename} size ({current_size} bytes, force={force}) "
                    f"meets rotation criteria. Rotating..."
                )
                success, msg = rotate_single_log(
                    file_path=file_path,
                    base_dir=base,
                    retention_files=retention_files,
                    suricata_pid=suricata_pid,
                )
                if success:
                    results["rotated"].append({
                        "file": filename,
                        "old_size_bytes": current_size,
                        "message": msg,
                    })
                else:
                    results["errors"].append({
                        "file": filename,
                        "error": msg,
                    })
            else:
                results["skipped"].append({
                    "file": filename,
                    "size_bytes": current_size,
                    "threshold_bytes": max_size_bytes,
                })

        return results

    finally:
        _rotation_lock.release()


def get_ids_log_metrics(log_dir: Optional[str] = None) -> Dict[str, Any]:
    """
    Returns actual filesystem statistics for IDS logs without mock data.
    Exposes file sizes, archive counts, active inodes, and retention policies.
    """
    base = log_dir or get_default_ids_log_dir()
    retention_files = int(os.getenv("IDS_LOG_RETENTION_FILES", "7"))
    rotation_size_mb = int(os.getenv("IDS_LOG_ROTATION_SIZE_MB", "100"))
    interval_seconds = int(os.getenv("IDS_LOG_ROTATION_INTERVAL_SECONDS", "60"))

    total_active_bytes = 0
    total_archive_bytes = 0
    files_info = {}

    for name in MANAGED_LOG_FILES:
        active_path = os.path.join(base, name)
        active_size = 0
        active_inode = None
        exists = os.path.exists(active_path)

        if exists:
            try:
                st = os.stat(active_path)
                active_size = st.st_size
                active_inode = st.st_ino
                total_active_bytes += active_size
            except Exception:
                pass

        # Scan for rotated archives of this file
        archives = []
        for idx in range(1, retention_files + 10):
            arch_name = f"{name}.{idx}.gz"
            arch_path = os.path.join(base, arch_name)
            if os.path.exists(arch_path):
                try:
                    arch_size = os.path.getsize(arch_path)
                    total_archive_bytes += arch_size
                    archives.append({
                        "name": arch_name,
                        "index": idx,
                        "size_bytes": arch_size,
                        "size_mb": round(arch_size / (1024 * 1024), 2),
                    })
                except Exception:
                    pass

        files_info[name] = {
            "exists": exists,
            "size_bytes": active_size,
            "size_mb": round(active_size / (1024 * 1024), 2),
            "inode": active_inode,
            "archive_count": len(archives),
            "archives": archives,
        }

    return {
        "log_directory": base,
        "total_active_bytes": total_active_bytes,
        "total_active_mb": round(total_active_bytes / (1024 * 1024), 2),
        "total_archive_bytes": total_archive_bytes,
        "total_archive_mb": round(total_archive_bytes / (1024 * 1024), 2),
        "grand_total_bytes": total_active_bytes + total_archive_bytes,
        "grand_total_mb": round((total_active_bytes + total_archive_bytes) / (1024 * 1024), 2),
        "retention_files": retention_files,
        "rotation_size_mb": rotation_size_mb,
        "rotation_interval_seconds": interval_seconds,
        "rotation_worker_running": is_rotation_worker_running(),
        "files": files_info,
    }


def is_rotation_worker_running() -> bool:
    """Returns True if the background rotation worker thread is alive."""
    global _rotation_thread
    return bool(_rotation_thread and _rotation_thread.is_alive())


def start_rotation_thread(app=None, interval_seconds: Optional[int] = None) -> bool:
    """
    Spawns background daemon thread to periodically evaluate log sizes and rotate.
    Safe against duplicate spawns.
    """
    global _rotation_thread, _rotation_stop_event

    if _rotation_thread and _rotation_thread.is_alive():
        logger.debug("[IDS Log Rotation] Worker thread already active.")
        return True

    if interval_seconds is None:
        interval_seconds = int(os.getenv("IDS_LOG_ROTATION_INTERVAL_SECONDS", "60"))

    _rotation_stop_event.clear()

    def rotation_worker():
        logger.info(f"[IDS Log Rotation] Background rotation worker started (interval: {interval_seconds}s).")
        while not _rotation_stop_event.is_set():
            try:
                if app:
                    with app.app_context():
                        rotate_ids_logs()
                else:
                    rotate_ids_logs()
            except Exception as e:
                logger.error(f"[IDS Log Rotation] Background check error: {e}")

            # Sleep in increments so stop event responds immediately
            _rotation_stop_event.wait(timeout=interval_seconds)

        logger.info("[IDS Log Rotation] Background rotation worker stopped.")

    _rotation_thread = threading.Thread(target=rotation_worker, name="ids-log-rotator", daemon=True)
    _rotation_thread.start()
    return True


def stop_rotation_thread(timeout: float = 3.0) -> bool:
    """Signals background rotation worker to stop and waits for termination."""
    global _rotation_thread, _rotation_stop_event

    if not _rotation_thread or not _rotation_thread.is_alive():
        return True

    _rotation_stop_event.set()
    _rotation_thread.join(timeout=timeout)
    is_stopped = not _rotation_thread.is_alive()
    if not is_stopped:
        logger.warning("[IDS Log Rotation] Worker thread did not terminate within timeout.")
    return is_stopped
