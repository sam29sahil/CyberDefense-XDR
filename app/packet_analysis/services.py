"""
CyberDefense XDR
Packet Analysis Services
Provides secure PCAP upload validation, TShark extraction (protocols, endpoints,
conversations, packet listings, dissection trees, hex dumps), and PostgreSQL persistence.
"""

import hashlib
import json
import logging
import math
import os
import re
import shutil
import subprocess
import uuid
from datetime import datetime

from flask import current_app
from werkzeug.utils import secure_filename

from app.extensions import db
from app.packet_analysis.models import PacketAnalysis

logger = logging.getLogger(__name__)

# Constants and Configuration
UPLOAD_FOLDER = os.path.join(os.getcwd(), "instance", "pcap_uploads")
MAX_PCAP_UPLOAD_MB = int(os.getenv("MAX_PCAP_UPLOAD_MB", "50"))
MAX_PCAP_UPLOAD_BYTES = MAX_PCAP_UPLOAD_MB * 1024 * 1024
TSHARK_TIMEOUT_SECONDS = int(os.getenv("TSHARK_TIMEOUT_SECONDS", "30"))
ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}

TSHARK_BIN = "/usr/bin/tshark" if os.path.exists("/usr/bin/tshark") else (shutil.which("tshark") or "tshark")
CAPINFOS_BIN = "/usr/bin/capinfos" if os.path.exists("/usr/bin/capinfos") else (shutil.which("capinfos") or "capinfos")

# Magic byte signatures
PCAP_MAGIC_NUMBERS = {
    b"\xa1\xb2\xc3\xd4",  # Standard PCAP (microsecond)
    b"\xd4\xc3\xb2\xa1",  # Swapped PCAP (microsecond)
    b"\xa1\xb2\x3c\x4d",  # Standard PCAP (nanosecond)
    b"\x4d\x3c\xb2\xa1",  # Swapped PCAP (nanosecond)
    b"\x0a\x0d\x0d\x0a",  # PCAPNG
}

# Regex for safe Wireshark display filter characters
SAFE_FILTER_PATTERN = re.compile(r"^[a-zA-Z0-9_\-\.\:\s\(\)\=\!\<\>\&\|\'\"\*\/\[\]\$\+\,\~]+$")


def ensure_upload_dir():
    """Ensures the PCAP upload storage directory exists with restricted permissions."""
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER, mode=0o750, exist_ok=True)
    return UPLOAD_FOLDER


# ==============================================================================
# PCAP Upload & Validation
# ==============================================================================

def validate_pcap_header(file_path):
    """
    Validates file magic bytes to confirm standard PCAP or PCAPNG.
    Returns (is_valid: bool, file_type: str).
    """
    try:
        with open(file_path, "rb") as f:
            header = f.read(4)
            if len(header) < 4:
                return False, "unknown"
            if header == b"\x0a\x0d\x0d\x0a":
                return True, "pcapng"
            if header in PCAP_MAGIC_NUMBERS:
                return True, "pcap"
        return False, "unknown"
    except Exception as e:
        logger.warning(f"Failed to read header of {file_path}: {e}")
        return False, "unknown"


def save_uploaded_pcap(file_storage, user_id=None, ids_event_id=None, force_reanalyze=False):
    """
    Securely streams and saves an uploaded PCAP/PCAPNG file.
    Validates file extension, size limit, and PCAP magic bytes.
    Computes SHA-256 during streaming.
    Detects duplicates and reuses existing completed analysis unless force_reanalyze=True.
    Returns (PacketAnalysis instance, is_new: bool).
    """
    if not file_storage or not file_storage.filename:
        raise ValueError("No file provided.")

    original_filename = secure_filename(file_storage.filename)
    if not original_filename:
        original_filename = "capture.pcap"

    _, ext = os.path.splitext(original_filename.lower())
    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(f"Unsupported file format '{ext}'. Allowed extensions: {', '.join(ALLOWED_EXTENSIONS)}")

    upload_dir = ensure_upload_dir()
    stored_name = f"{uuid.uuid4().hex}{ext}"
    temp_path = os.path.join(upload_dir, stored_name)

    # Stream file to disk while enforcing max size and calculating SHA-256
    sha256_hasher = hashlib.sha256()
    total_bytes = 0

    try:
        with open(temp_path, "wb") as dst:
            while True:
                chunk = file_storage.stream.read(65536)
                if not chunk:
                    break
                total_bytes += len(chunk)
                if total_bytes > MAX_PCAP_UPLOAD_BYTES:
                    raise ValueError(f"Uploaded file exceeds maximum limit of {MAX_PCAP_UPLOAD_MB} MB.")
                sha256_hasher.update(chunk)
                dst.write(chunk)
    except Exception as e:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
        raise e

    if total_bytes == 0:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise ValueError("Uploaded file is empty.")

    sha256_hex = sha256_hasher.hexdigest()

    # Verify PCAP / PCAPNG header
    is_valid, detected_type = validate_pcap_header(temp_path)
    if not is_valid:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise ValueError("The uploaded file does not have a valid PCAP or PCAPNG header.")

    # Quick TShark probe to verify file can be read
    try:
        probe = subprocess.run(
            [TSHARK_BIN, "-r", temp_path, "-c", "1"],
            capture_output=True,
            text=True,
            timeout=10,
            shell=False,
        )
        if probe.returncode != 0:
            if os.path.exists(temp_path):
                os.remove(temp_path)
            error_detail = probe.stderr.strip().split("\n")[0] if probe.stderr else "Unreadable PCAP"
            raise ValueError(f"Corrupt or invalid capture file: {error_detail}")
    except subprocess.TimeoutExpired:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise ValueError("TShark timed out validating capture file.")
    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise e

    # Duplicate SHA-256 handling
    existing = PacketAnalysis.query.filter_by(sha256=sha256_hex, status="completed").first()
    if existing and not force_reanalyze:
        # Re-use existing completed analysis and clean up duplicate upload
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except OSError:
                pass
        return existing, False

    # Persist record in PostgreSQL
    analysis = PacketAnalysis(
        user_id=user_id,
        filename=original_filename,
        stored_filename=stored_name,
        storage_path=temp_path,
        file_size=total_bytes,
        file_type=detected_type,
        sha256=sha256_hex,
        status="uploaded",
        ids_event_id=ids_event_id,
    )
    db.session.add(analysis)
    db.session.commit()

    return analysis, True


# ==============================================================================
# TShark Analysis Execution
# ==============================================================================

def run_pcap_analysis(analysis_id):
    """
    Executes deep analysis using capinfos and TShark on the stored PCAP.
    Extracts high-level capture statistics, protocol hierarchy, conversations,
    and endpoints. Updates PostgreSQL record and logs to SIEM.
    """
    analysis = get_analysis_by_id(analysis_id)
    if not analysis:
        raise ValueError(f"Analysis '{analysis_id}' not found.")

    if not os.path.exists(analysis.storage_path):
        analysis.status = "failed"
        analysis.error_message = "Capture file missing from storage."
        db.session.commit()
        raise FileNotFoundError(f"Storage path {analysis.storage_path} does not exist.")

    analysis.status = "running"
    analysis.error_message = None
    db.session.commit()

    try:
        # 1. Capture Metadata via capinfos
        meta = _extract_capinfos_metadata(analysis.storage_path)
        analysis.packet_count = meta.get("packet_count", 0)
        analysis.duration = meta.get("duration", 0.0)
        analysis.first_packet_time = meta.get("first_packet_time")
        analysis.last_packet_time = meta.get("last_packet_time")
        analysis.encapsulation = meta.get("encapsulation", "Ethernet")
        analysis.summary_metadata = meta.get("raw_summary", {})

        # 2. Protocol Hierarchy via tshark -q -z io,phs
        protocol_stats = _extract_protocol_hierarchy(analysis.storage_path, analysis.packet_count)
        analysis.protocol_stats = protocol_stats

        # 3. IP and Transport Conversations via tshark -q -z conv,ip
        conversation_stats = _extract_conversations(analysis.storage_path)
        analysis.conversation_stats = conversation_stats

        # 4. Endpoints via tshark -q -z endpoints,ip
        endpoint_stats = _extract_endpoints(analysis.storage_path)
        analysis.endpoint_stats = endpoint_stats

        analysis.status = "completed"
        db.session.commit()

        # 5. Dispatch lightweight SIEM audit event
        _dispatch_siem_event(analysis)

        logger.info(f"Packet analysis {analysis.id} completed: {analysis.packet_count} packets analyzed.")
        return analysis

    except Exception as e:
        logger.exception(f"Packet analysis {analysis.id} failed: {e}")
        analysis.status = "failed"
        analysis.error_message = str(e)[:500]
        db.session.commit()
        raise RuntimeError(f"TShark packet analysis failed: {e}")


def _extract_capinfos_metadata(file_path):
    """Runs capinfos to extract packet count, duration, first/last timestamps, encapsulation."""
    result = {
        "packet_count": 0,
        "duration": 0.0,
        "first_packet_time": None,
        "last_packet_time": None,
        "encapsulation": "Ethernet",
        "raw_summary": {},
    }

    cmd = [CAPINFOS_BIN, "-a", "-e", "-c", "-u", "-d", "-E", file_path]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TSHARK_TIMEOUT_SECONDS, shell=False)
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                if ":" in line:
                    key, val = line.split(":", 1)
                    k = key.strip().lower()
                    v = val.strip()
                    result["raw_summary"][key.strip()] = v

                    if "number of packets" in k:
                        try:
                            result["packet_count"] = int(v.replace(",", ""))
                        except ValueError:
                            pass
                    elif "capture duration" in k:
                        try:
                            parts = v.split()
                            result["duration"] = float(parts[0].replace(",", ""))
                        except (ValueError, IndexError):
                            pass
                    elif "file encapsulation" in k:
                        result["encapsulation"] = v
                    elif "earliest packet time" in k:
                        result["first_packet_time"] = _parse_capinfos_dt(v)
                    elif "latest packet time" in k:
                        result["last_packet_time"] = _parse_capinfos_dt(v)
    except Exception as e:
        logger.warning(f"Capinfos failed for {file_path}: {e}")

    # Fallback to TShark if packet_count is still 0
    if result["packet_count"] == 0:
        try:
            cmd_fb = [TSHARK_BIN, "-r", file_path, "-T", "fields", "-e", "frame.number"]
            proc_fb = subprocess.run(cmd_fb, capture_output=True, text=True, timeout=TSHARK_TIMEOUT_SECONDS, shell=False)
            if proc_fb.returncode == 0:
                lines = [line for line in proc_fb.stdout.splitlines() if line.strip()]
                result["packet_count"] = len(lines)
        except Exception as e:
            logger.warning(f"TShark packet count fallback failed: {e}")

    return result


def _parse_capinfos_dt(dt_str):
    """Safely parses timestamp strings output by capinfos."""
    if not dt_str:
        return None
    # Example format: 2023-11-15 03:43:20.000000
    try:
        # Strip microsecond precision if needed
        clean_str = dt_str.split(".")[0]
        return datetime.strptime(clean_str, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def _extract_protocol_hierarchy(file_path, total_packets=0):
    """
    Runs `tshark -r <file> -q -z io,phs` and parses the protocol hierarchy tree.
    Returns a dictionary with structured protocols and percentage metrics.
    """
    cmd = [TSHARK_BIN, "-r", file_path, "-q", "-z", "io,phs"]
    protocols = []
    protocol_counts = {}

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TSHARK_TIMEOUT_SECONDS, shell=False)
        if proc.returncode == 0:
            lines = proc.stdout.splitlines()
            start_parsing = False

            for line in lines:
                if "Protocol Hierarchy Statistics" in line:
                    start_parsing = True
                    continue
                if not start_parsing:
                    continue
                if line.startswith("===") or line.startswith("Filter:"):
                    continue
                if "frames:" in line and "bytes:" in line:
                    # Line format: '  ip                                     frames:2 bytes:148'
                    match = re.match(r"^(\s*)([a-zA-Z0-9_\-]+)\s+frames:(\d+)\s+bytes:(\d+)", line)
                    if match:
                        indent = len(match.group(1)) // 2
                        proto_name = match.group(2)
                        frames = int(match.group(3))
                        byte_count = int(match.group(4))
                        pct = round((frames / total_packets * 100), 1) if total_packets > 0 else 0.0

                        entry = {
                            "name": proto_name.upper(),
                            "protocol": proto_name,
                            "frames": frames,
                            "bytes": byte_count,
                            "percent": pct,
                            "depth": indent,
                        }
                        protocols.append(entry)
                        protocol_counts[proto_name.upper()] = frames

    except Exception as e:
        logger.warning(f"Failed to extract protocol hierarchy: {e}")

    return {
        "protocols": protocols,
        "counts": protocol_counts,
        "total_packets": total_packets,
    }


def _extract_conversations(file_path):
    """
    Runs `tshark -r <file> -q -z conv,ip` and parses IP conversations.
    Returns list of top conversation flows.
    """
    conversations = []
    cmd = [TSHARK_BIN, "-r", file_path, "-q", "-z", "conv,ip"]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TSHARK_TIMEOUT_SECONDS, shell=False)
        if proc.returncode == 0:
            lines = proc.stdout.splitlines()
            start_parsing = False

            for line in lines:
                if "<->" in line and "Frames" not in line and "Filter" not in line:
                    parts = line.split()
                    # Example parts: ['127.0.0.1', '<->', '127.0.0.1', '0', '0', 'bytes', '1', '74', 'bytes', '1', '74', 'bytes', ...]
                    if len(parts) >= 11 and parts[1] == "<->":
                        src_ip = parts[0]
                        dst_ip = parts[2]
                        try:
                            # Frame count total is usually before total bytes
                            total_frames = int(parts[9])
                            total_bytes = int(parts[10])
                        except (ValueError, IndexError):
                            total_frames = 1
                            total_bytes = 0

                        conversations.append({
                            "source": src_ip,
                            "destination": dst_ip,
                            "protocol": "IPv4",
                            "frames": total_frames,
                            "bytes": total_bytes,
                        })

    except Exception as e:
        logger.warning(f"Failed to extract IP conversations: {e}")

    # Also capture TCP conversations if available
    try:
        cmd_tcp = [TSHARK_BIN, "-r", file_path, "-q", "-z", "conv,tcp"]
        proc_tcp = subprocess.run(cmd_tcp, capture_output=True, text=True, timeout=TSHARK_TIMEOUT_SECONDS, shell=False)
        if proc_tcp.returncode == 0:
            for line in proc_tcp.stdout.splitlines():
                if "<->" in line and "Frames" not in line:
                    parts = line.split()
                    if len(parts) >= 11 and parts[1] == "<->":
                        src = parts[0]
                        dst = parts[2]
                        try:
                            total_frames = int(parts[9])
                            total_bytes = int(parts[10])
                        except (ValueError, IndexError):
                            total_frames = 1
                            total_bytes = 0

                        conversations.append({
                            "source": src,
                            "destination": dst,
                            "protocol": "TCP",
                            "frames": total_frames,
                            "bytes": total_bytes,
                        })
    except Exception as e:
        logger.warning(f"Failed to extract TCP conversations: {e}")

    # Sort conversations by frames descending and limit to top 50
    conversations.sort(key=lambda c: c.get("frames", 0), reverse=True)
    return conversations[:50]


def _extract_endpoints(file_path):
    """
    Runs `tshark -r <file> -q -z endpoints,ip` and parses IP endpoints.
    Returns list of top IP endpoints.
    """
    endpoints = []
    cmd = [TSHARK_BIN, "-r", file_path, "-q", "-z", "endpoints,ip"]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TSHARK_TIMEOUT_SECONDS, shell=False)
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                if line.startswith("===") or "IPv4 Endpoints" in line or "Packets" in line or "Filter" in line:
                    continue
                parts = line.split()
                # Format: IP | Packets | Bytes | Tx Packets | Tx Bytes | Rx Packets | Rx Bytes
                if len(parts) >= 3 and "." in parts[0]:
                    ip = parts[0]
                    try:
                        packets = int(parts[1])
                        byte_count = int(parts[2])
                    except ValueError:
                        continue

                    endpoints.append({
                        "ip": ip,
                        "packets": packets,
                        "bytes": byte_count,
                    })
    except Exception as e:
        logger.warning(f"Failed to extract IP endpoints: {e}")

    endpoints.sort(key=lambda e: e.get("packets", 0), reverse=True)
    return endpoints[:50]


def _dispatch_siem_event(analysis):
    """Dispatches a structured audit event to SIEM upon analysis completion."""
    try:
        from app.siem.services import ingest_event as siem_ingest
        siem_ingest({
            "source": "Packet Analysis",
            "severity": "info",
            "category": "Packet Inspection",
            "host": "localhost",
            "message": f"PCAP analysis completed for {analysis.filename}: {analysis.packet_count} packets analyzed ({analysis.file_type}).",
            "fields": {
                "analysis_id": analysis.id,
                "analysis_uuid": analysis.analysis_uuid,
                "filename": analysis.filename,
                "sha256": analysis.sha256,
                "packet_count": analysis.packet_count,
                "duration": analysis.duration,
                "encapsulation": analysis.encapsulation,
            },
        })
    except Exception as e:
        logger.warning(f"Failed to dispatch Packet Analysis event to SIEM: {e}")


# ==============================================================================
# Safe Wireshark Display Filter Validation
# ==============================================================================

def validate_display_filter(filter_str):
    """
    Validates Wireshark display filter syntax securely without shell execution.
    Enforces maximum length, regex whitelist, and dry-run syntax check via TShark.
    """
    if not filter_str or not filter_str.strip():
        return ""

    cleaned = filter_str.strip()
    if len(cleaned) > 200:
        raise ValueError("Display filter exceeds maximum allowed length of 200 characters.")

    if not SAFE_FILTER_PATTERN.match(cleaned):
        raise ValueError("Display filter contains disallowed characters or potential injection tokens.")

    # Disallow dangerous shell patterns
    forbidden_tokens = [";", "`", "$", "\\", "\n", "\r", "\0"]
    for token in forbidden_tokens:
        if token in cleaned:
            raise ValueError(f"Display filter contains forbidden character '{token}'.")

    # Dry-run validation via tshark against a 24-byte empty PCAP header
    try:
        ensure_upload_dir()
        empty_probe_path = os.path.join(UPLOAD_FOLDER, ".empty_probe.pcap")
        if not os.path.exists(empty_probe_path):
            import struct
            with open(empty_probe_path, "wb") as f:
                f.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))

        test_cmd = [TSHARK_BIN, "-r", empty_probe_path, "-Y", cleaned, "-c", "1"]
        proc = subprocess.run(
            test_cmd,
            capture_output=True,
            text=True,
            timeout=3,
            shell=False,
        )
        if proc.returncode != 0:
            err_msg = proc.stderr.strip().split("\n")[0] if proc.stderr else "Syntax error in filter."
            raise ValueError(f"Invalid Wireshark filter: {err_msg}")
    except subprocess.TimeoutExpired:
        raise ValueError("Filter validation timed out.")
    except Exception as e:
        if isinstance(e, ValueError):
            raise e
        logger.warning(f"Filter dry-run test error: {e}")

    return cleaned


# ==============================================================================
# Paginated Packet Retrieval & Dissection
# ==============================================================================

def get_analysis_packets(analysis_id, page=1, per_page=50, display_filter=None, search=None):
    """
    Extracts a paginated, filterable listing of packets directly from the PCAP via TShark.
    Supports display filters and text search.
    """
    analysis = get_analysis_by_id(analysis_id)
    if not analysis:
        raise ValueError(f"Analysis '{analysis_id}' not found.")

    if not os.path.exists(analysis.storage_path):
        raise FileNotFoundError("PCAP storage file not found.")

    page = max(1, int(page))
    per_page = max(1, min(int(per_page), 200))

    valid_filter = ""
    if display_filter:
        valid_filter = validate_display_filter(display_filter)

    cmd = [
        TSHARK_BIN,
        "-r", analysis.storage_path,
        "-T", "fields",
        "-e", "frame.number",
        "-e", "frame.time_epoch",
        "-e", "frame.time",
        "-e", "ip.src",
        "-e", "ipv6.src",
        "-e", "eth.src",
        "-e", "ip.dst",
        "-e", "ipv6.dst",
        "-e", "eth.dst",
        "-e", "_ws.col.Protocol",
        "-e", "frame.len",
        "-e", "_ws.col.Info",
        "-E", "header=y",
        "-E", "separator=\t",
    ]

    if valid_filter:
        cmd.extend(["-Y", valid_filter])

    packets = []
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TSHARK_TIMEOUT_SECONDS, shell=False)
        if proc.returncode != 0 and proc.stderr:
            raise RuntimeError(f"TShark packet read failed: {proc.stderr.strip().splitlines()[0]}")

        lines = proc.stdout.splitlines()
        # First line is header
        data_lines = lines[1:] if len(lines) > 1 else []

        search_lower = search.lower().strip() if search else None

        for line in data_lines:
            parts = line.split("\t")
            if len(parts) >= 12:
                frame_no = parts[0].strip()
                time_epoch = parts[1].strip()
                time_str = parts[2].strip()
                src_ip = parts[3].strip() or parts[4].strip() or parts[5].strip() or "-"
                dst_ip = parts[6].strip() or parts[7].strip() or parts[8].strip() or "-"
                protocol = parts[9].strip() or "Unknown"
                length = parts[10].strip() or "0"
                info = parts[11].strip() if len(parts) > 11 else ""

                # Optional text search filter across fields
                if search_lower:
                    combined = f"{frame_no} {src_ip} {dst_ip} {protocol} {info}".lower()
                    if search_lower not in combined:
                        continue

                packets.append({
                    "number": int(frame_no) if frame_no.isdigit() else frame_no,
                    "time_epoch": float(time_epoch) if time_epoch else None,
                    "time": time_str,
                    "source": src_ip,
                    "destination": dst_ip,
                    "protocol": protocol,
                    "length": int(length) if length.isdigit() else 0,
                    "info": info,
                })

    except subprocess.TimeoutExpired:
        raise RuntimeError("TShark packet extraction timed out.")

    total = len(packets)
    pages = max(1, math.ceil(total / per_page))
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    items = packets[start_idx:end_idx]

    return {
        "items": items,
        "packets": items,
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": pages,
        "has_prev": page > 1,
        "has_next": page < pages,
    }


def get_packet_detail(analysis_id, packet_number):
    """
    Extracts structured protocol dissection tree and formatted hex dump for a single packet.
    """
    analysis = get_analysis_by_id(analysis_id)
    if not analysis:
        raise ValueError(f"Analysis '{analysis_id}' not found.")

    if not str(packet_number).isdigit() or int(packet_number) < 1:
        raise ValueError("Invalid packet number.")

    pkt_num = int(packet_number)
    filter_expr = f"frame.number == {pkt_num}"

    layers = {}
    hexdump = ""

    # 1. Fetch structured JSON dissection tree
    cmd_json = [TSHARK_BIN, "-r", analysis.storage_path, "-Y", filter_expr, "-T", "json"]
    try:
        proc_json = subprocess.run(cmd_json, capture_output=True, text=True, timeout=15, shell=False)
        if proc_json.returncode == 0 and proc_json.stdout.strip():
            json_data = json.loads(proc_json.stdout)
            if json_data and isinstance(json_data, list) and len(json_data) > 0:
                layers = json_data[0].get("_source", {}).get("layers", {})
    except Exception as e:
        logger.warning(f"Failed to extract packet JSON tree: {e}")

    # 2. Fetch raw hex dump
    cmd_hex = [TSHARK_BIN, "-r", analysis.storage_path, "-Y", filter_expr, "-x"]
    try:
        proc_hex = subprocess.run(cmd_hex, capture_output=True, text=True, timeout=15, shell=False)
        if proc_hex.returncode == 0:
            hexdump = proc_hex.stdout
    except Exception as e:
        logger.warning(f"Failed to extract packet hex dump: {e}")

    return {
        "packet_number": pkt_num,
        "layers": layers,
        "hexdump": hexdump,
    }


# ==============================================================================
# Model Query & Lifecycle Helpers
# ==============================================================================

def get_analysis_by_id(analysis_id):
    """Retrieves a PacketAnalysis record by primary key or UUID."""
    if not analysis_id:
        return None
    if str(analysis_id).isdigit():
        record = db.session.get(PacketAnalysis, int(analysis_id))
        if record:
            return record
    return PacketAnalysis.query.filter_by(analysis_uuid=str(analysis_id).strip()).first()


def get_packet_analyses(filters=None, page=1, per_page=20):
    """Retrieves paginated PacketAnalysis records with search and status filters."""
    filters = filters or {}
    q = PacketAnalysis.query

    status = filters.get("status")
    if status:
        q = q.filter(PacketAnalysis.status == str(status).lower().strip())

    search = filters.get("search") or filters.get("q")
    if search:
        term = f"%{str(search).strip()}%"
        q = q.filter(
            db.or_(
                PacketAnalysis.filename.ilike(term),
                PacketAnalysis.sha256.ilike(term),
                PacketAnalysis.encapsulation.ilike(term),
            )
        )

    total = q.count()
    pagination = q.order_by(PacketAnalysis.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)

    return {
        "items": [item.to_dict() for item in pagination.items],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": pagination.pages,
        "has_prev": pagination.has_prev,
        "has_next": pagination.has_next,
    }


def delete_analysis(analysis_id):
    """Deletes analysis record and removes stored PCAP file from disk."""
    analysis = get_analysis_by_id(analysis_id)
    if not analysis:
        raise ValueError(f"Analysis '{analysis_id}' not found.")

    # Remove storage file
    if os.path.exists(analysis.storage_path):
        try:
            os.remove(analysis.storage_path)
        except OSError as e:
            logger.warning(f"Failed to remove file {analysis.storage_path}: {e}")

    db.session.delete(analysis)
    db.session.commit()
    return True


def get_packet_analysis_dashboard_stats():
    """Calculates KPIs and aggregates for the Packet Analysis Dashboard."""
    total_analyses = PacketAnalysis.query.count()
    completed_analyses = PacketAnalysis.query.filter_by(status="completed").count()
    running_analyses = PacketAnalysis.query.filter_by(status="running").count()
    failed_analyses = PacketAnalysis.query.filter_by(status="failed").count()

    total_packets_result = db.session.query(db.func.sum(PacketAnalysis.packet_count)).scalar()
    total_packets = int(total_packets_result or 0)

    recent_query = PacketAnalysis.query.order_by(PacketAnalysis.created_at.desc()).limit(10).all()
    recent = [a.to_dict() for a in recent_query]

    return {
        "kpis": {
            "totalAnalyses": total_analyses,
            "completedAnalyses": completed_analyses,
            "runningAnalyses": running_analyses,
            "failedAnalyses": failed_analyses,
            "totalPackets": total_packets,
        },
        "recent": recent,
    }
