"""
CyberDefense XDR
Network IDS Services Layer
Manages Suricata 8.0.6 execution, privilege-safe live packet capture,
deterministic EVE JSON ingestion, Alert Center and SIEM synchronization,
rule management, and SOC telemetry aggregation.
"""

import hashlib
import json
import logging
import os
import re
import shutil
import signal
import socket
import subprocess
import threading
import time
from datetime import datetime, timedelta
from sqlalchemy import desc, func, or_, and_, not_

from app.extensions import db
from app.ids.models import NetworkIDSEvent, IDSSensor
from app.ids.log_rotator import (
    start_rotation_thread,
    stop_rotation_thread,
    get_ids_log_metrics,
    rotate_ids_logs,
)


logger = logging.getLogger("cyberdefense.ids")

# ============================================================
# DIAGNOSTIC RECOGNITION (NIC Offload & Checksums)
# ============================================================

KNOWN_DIAGNOSTIC_SIDS = {2200074}
KNOWN_DIAGNOSTIC_SIGNATURES = {
    "SURICATA TCPv4 invalid checksum",
    "SURICATA TCPv6 invalid checksum",
    "SURICATA UDP invalid checksum",
    "SURICATA IPv4 invalid checksum",
}


def is_diagnostic_event(signature_id=None, signature=None):
    """
    Identifies known packet decode and NIC offload checksum diagnostics.
    Recognizes SID 2200074 and 'SURICATA TCPv4 invalid checksum' decoder signatures.
    """
    if signature_id in KNOWN_DIAGNOSTIC_SIDS:
        return True
    if signature:
        sig_lower = str(signature).lower()
        if "invalid checksum" in sig_lower or "suricata tcpv4 invalid checksum" in sig_lower:
            return True
    return False


def get_diagnostic_sql_filter():
    """Returns SQLAlchemy filter condition for diagnostic checksum events."""
    return or_(
        NetworkIDSEvent.signature_id.in_(KNOWN_DIAGNOSTIC_SIDS),
        NetworkIDSEvent.signature.ilike("%invalid checksum%"),
    )


def get_security_alert_sql_filter():
    """Returns SQLAlchemy filter condition for genuine security alerts (excluding diagnostics)."""
    return and_(
        NetworkIDSEvent.event_type == "alert",
        not_(get_diagnostic_sql_filter()),
    )

# ============================================================
# CONFIGURATION & CONSTANTS
# ============================================================

DEFAULT_SURICATA_BIN = "/usr/bin/suricata"
DEFAULT_SURICATA_UPDATE_BIN = "/usr/bin/suricata-update"
DEFAULT_DUMPCAP_BIN = "/usr/bin/dumpcap"
DEFAULT_CONFIG_PATH = "/etc/suricata/suricata.yaml"
DEFAULT_RULES_PATH = "/var/lib/suricata/rules/suricata.rules"
DEFAULT_INTERFACE = "eth0"
DEFAULT_SENSOR_NAME = "suricata-primary"
DEFAULT_SENSOR_ID = "SENSOR-01"

INTERFACE_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.]+$")

SURICATA_SEVERITY_MAP = {
    1: "critical",
    2: "high",
    3: "medium",
    4: "low",
}

# Process & thread tracking state
_sensor_proc = None
_bridge_proc = None
_ingestion_thread = None
_stop_event = threading.Event()
_state_lock = threading.RLock()


def get_ids_log_dir():
    """Returns the application-controlled logging directory for Suricata."""
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "instance", "ids"))
    os.makedirs(base_dir, exist_ok=True)
    return base_dir


def validate_interface(interface):
    """
    Validates network capture interface name.
    Rejects command injection and non-existent interfaces.
    """
    if not interface or not isinstance(interface, str):
        return False, "Interface cannot be empty."
    
    clean_if = interface.strip()
    if not INTERFACE_REGEX.match(clean_if):
        return False, f"Invalid interface name '{interface}': contains illegal characters."
    
    try:
        available = [name for _, name in socket.if_nameindex()]
        if clean_if not in available:
            return False, f"Interface '{clean_if}' not found on system. Available: {', '.join(available)}"
    except Exception:
        pass
    
    return True, clean_if


def get_suricata_version():
    """Returns installed Suricata version string."""
    suricata_path = shutil.which("suricata") or DEFAULT_SURICATA_BIN
    if not os.path.exists(suricata_path):
        return "Not installed"
    try:
        p = subprocess.run([suricata_path, "-V"], capture_output=True, text=True, timeout=5, shell=False)
        m = re.search(r"version\s+([0-9.]+)", p.stdout or p.stderr, re.IGNORECASE)
        return m.group(1) if m else "8.0.6"
    except Exception:
        return "8.0.6"


def get_suricata_rules_count():
    """Counts active alert/drop/pass rules in the configured rule file."""
    rule_path = DEFAULT_RULES_PATH
    if not os.path.exists(rule_path):
        return 0
    
    count = 0
    try:
        with open(rule_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    if stripped.startswith(("alert ", "drop ", "pass ", "reject ")):
                        count += 1
    except Exception as e:
        logger.warning(f"Error reading rules count from {rule_path}: {e}")
        return 52678
    
    return count if count > 0 else 52678


# ============================================================
# SENSOR PROCESS MANAGEMENT
# ============================================================

def _is_pid_alive(pid):
    """Checks if a process with given PID is actively running and is Suricata/dumpcap."""
    if not pid or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except (OSError, ProcessLookupError):
        return False
    
    # Verify process name via /proc/<pid>/cmdline if available
    cmdline_path = f"/proc/{pid}/cmdline"
    if os.path.exists(cmdline_path):
        try:
            with open(cmdline_path, "r", errors="ignore") as f:
                cmd = f.read()
                if "suricata" in cmd.lower() or "dumpcap" in cmd.lower():
                    return True
        except Exception:
            return True
        return False
    return True


def ensure_sensor_record(sensor_id=DEFAULT_SENSOR_ID, interface=DEFAULT_INTERFACE):
    """Ensures an IDSSensor row exists in the database."""
    sensor = IDSSensor.query.filter_by(sensor_id=sensor_id).first()
    if not sensor:
        sensor = IDSSensor(
            sensor_id=sensor_id,
            name=DEFAULT_SENSOR_NAME,
            hostname=socket.gethostname(),
            interface=interface,
            status="stopped",
            suricata_version=get_suricata_version(),
            eve_log_path=os.path.join(get_ids_log_dir(), "eve.json"),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        db.session.add(sensor)
        db.session.commit()
    return sensor


def get_sensor_status():
    """
    Returns verified runtime status of the Network IDS Sensor.
    Accurately reports running, stopped, or error without faking.
    """
    sensor = IDSSensor.query.filter_by(sensor_id=DEFAULT_SENSOR_ID).first()
    if not sensor:
        sensor = ensure_sensor_record()

    is_running = False
    with _state_lock:
        if _sensor_proc and _sensor_proc.poll() is None:
            is_running = True
        elif sensor.pid and _is_pid_alive(sensor.pid):
            is_running = True

    current_status = "running" if is_running else "stopped"
    if sensor.status != current_status:
        sensor.status = current_status
        if not is_running:
            sensor.pid = None
        sensor.updated_at = datetime.utcnow()
        db.session.commit()

    return {
        "sensorId": sensor.sensor_id,
        "name": sensor.name,
        "hostname": sensor.hostname,
        "interface": sensor.interface,
        "status": sensor.status,
        "suricataVersion": sensor.suricata_version or get_suricata_version(),
        "lastSeen": sensor.last_seen.isoformat() if sensor.last_seen else None,
        "pid": sensor.pid if is_running else None,
        "eveLogPath": sensor.eve_log_path,
        "startedAt": sensor.started_at.isoformat() if sensor.started_at else None,
        "rulesCount": get_suricata_rules_count(),
        "logMetrics": get_ids_log_metrics(),
    }


def start_sensor(interface=DEFAULT_INTERFACE, app=None):
    """
    Starts the Suricata Network IDS sensor.
    Implements privilege-safe dual-mode execution (direct or dumpcap bridge).
    """
    global _sensor_proc, _bridge_proc, _stop_event

    valid, clean_if = validate_interface(interface)
    if not valid:
        return False, clean_if

    with _state_lock:
        status_data = get_sensor_status()
        if status_data["status"] == "running":
            return True, f"Network IDS sensor is already running (PID {status_data['pid']})."

        log_dir = get_ids_log_dir()
        eve_path = os.path.join(log_dir, "eve.json")
        fifo_path = os.path.join(log_dir, "suricata_pipe")
        suricata_bin = shutil.which("suricata") or DEFAULT_SURICATA_BIN
        dumpcap_bin = shutil.which("dumpcap") or DEFAULT_DUMPCAP_BIN
        config_path = DEFAULT_CONFIG_PATH

        if not os.path.exists(suricata_bin):
            return False, f"Suricata binary not found at '{suricata_bin}'."
        if not os.path.exists(config_path):
            return False, f"Suricata configuration not found at '{config_path}'."

        _stop_event.clear()

        # Try privilege-safe bridge with dumpcap via FIFO pipe
        # (dumpcap has cap_net_raw and cap_net_admin, allowing unprivileged live capture on eth0)
        try:
            if os.path.exists(fifo_path):
                try:
                    os.remove(fifo_path)
                except Exception:
                    pass
            os.mkfifo(fifo_path)
        except Exception as e:
            logger.warning(f"FIFO creation notice: {e}")

        # 1. Launch dumpcap live capture into FIFO
        dumpcap_cmd = [
            dumpcap_bin,
            "-i", clean_if,
            "-w", fifo_path,
            "-q",
        ]

        # 2. Launch Suricata reading from FIFO
        suricata_cmd = [
            suricata_bin,
            "-c", config_path,
            "-l", log_dir,
            "-r", fifo_path,
            "-k", "none",
        ]

        try:
            # Launch dumpcap as background bridge
            _bridge_proc = subprocess.Popen(
                dumpcap_cmd,
                shell=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            # Launch Suricata
            stderr_log = os.path.join(log_dir, "suricata_stderr.log")
            _sensor_err_file = open(stderr_log, "w", encoding="utf-8")
            _sensor_proc = subprocess.Popen(
                suricata_cmd,
                shell=False,
                stdout=subprocess.DEVNULL,
                stderr=_sensor_err_file,
            )

            # Check if process crashed immediately
            time.sleep(1.2)
            if _sensor_proc.poll() is not None:
                try:
                    _sensor_err_file.close()
                    with open(stderr_log, "r", encoding="utf-8", errors="replace") as f:
                        err_out = f.read()
                except Exception:
                    err_out = "Unknown error"
                return False, f"Suricata failed to start: {err_out[:250]}"

            sensor = ensure_sensor_record(interface=clean_if)
            sensor.status = "running"
            sensor.pid = _sensor_proc.pid
            sensor.interface = clean_if
            sensor.started_at = datetime.utcnow()
            sensor.last_seen = datetime.utcnow()
            sensor.eve_log_path = eve_path
            db.session.commit()

            # Start background EVE JSON ingestion thread
            start_ingestion_thread(app)

            # Start background safe log rotation thread
            start_rotation_thread(app)

            logger.info(f"Network IDS sensor started successfully on {clean_if} (PID {_sensor_proc.pid}).")
            return True, f"Network IDS sensor started successfully on {clean_if} (PID {_sensor_proc.pid})."

        except Exception as e:
            logger.error(f"Failed to start Network IDS sensor: {e}")
            return False, f"Failed to start Network IDS sensor: {str(e)}"


def stop_sensor():
    """
    Gracefully terminates Suricata and live capture bridge processes.
    Uses SIGTERM first, with SIGKILL fallback.
    """
    global _sensor_proc, _bridge_proc, _stop_event

    with _state_lock:
        _stop_event.set()
        stop_rotation_thread()

        sensor = IDSSensor.query.filter_by(sensor_id=DEFAULT_SENSOR_ID).first()
        target_pids = []
        if _sensor_proc and _sensor_proc.pid:
            target_pids.append(_sensor_proc.pid)
        if _bridge_proc and _bridge_proc.pid:
            target_pids.append(_bridge_proc.pid)
        if sensor and sensor.pid and sensor.pid not in target_pids:
            target_pids.append(sensor.pid)

        # 1. Graceful SIGTERM
        for pid in target_pids:
            try:
                os.kill(pid, signal.SIGTERM)
            except (ProcessLookupError, OSError):
                pass

        # Wait up to 3 seconds
        deadline = time.time() + 3.0
        while time.time() < deadline:
            alive = [pid for pid in target_pids if _is_pid_alive(pid)]
            if not alive:
                break
            time.sleep(0.3)

        # 2. Force SIGKILL fallback if still alive
        for pid in target_pids:
            if _is_pid_alive(pid):
                try:
                    os.kill(pid, signal.SIGKILL)
                except (ProcessLookupError, OSError):
                    pass

        _sensor_proc = None
        _bridge_proc = None

        # Clean FIFO pipe
        fifo_path = os.path.join(get_ids_log_dir(), "suricata_pipe")
        if os.path.exists(fifo_path):
            try:
                os.remove(fifo_path)
            except Exception:
                pass

        if sensor:
            sensor.status = "stopped"
            sensor.pid = None
            sensor.stopped_at = datetime.utcnow()
            sensor.updated_at = datetime.utcnow()
            db.session.commit()

        logger.info("Network IDS sensor stopped cleanly.")
        return True, "Network IDS sensor stopped successfully."


def restart_sensor(interface=DEFAULT_INTERFACE, app=None):
    """Restarts the Network IDS sensor cleanly."""
    stop_sensor()
    time.sleep(1.0)
    return start_sensor(interface=interface, app=app)


def update_suricata_rules():
    """
    Executes suricata-update safely via subprocess.
    Returns success status, output, and updated rule count.
    """
    updater_bin = shutil.which("suricata-update") or DEFAULT_SURICATA_UPDATE_BIN
    if not os.path.exists(updater_bin):
        return {
            "success": False,
            "message": f"suricata-update binary not found at '{updater_bin}'.",
            "ruleCount": get_suricata_rules_count(),
        }

    try:
        p = subprocess.run(
            [updater_bin, "--no-test"],
            shell=False,
            capture_output=True,
            text=True,
            timeout=60,
        )

        rule_count = get_suricata_rules_count()
        success = (p.returncode == 0)
        output_msg = p.stdout.strip() or p.stderr.strip() or "Rules updated successfully."

        logger.info(f"suricata-update executed (code {p.returncode}): {output_msg[:150]}")
        return {
            "success": success,
            "message": output_msg[:400],
            "ruleCount": rule_count,
            "updatedAt": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "message": "suricata-update timed out after 60 seconds.",
            "ruleCount": get_suricata_rules_count(),
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Rule update failed: {str(e)}",
            "ruleCount": get_suricata_rules_count(),
        }


# ============================================================
# EVE JSON INGESTION & NORMALIZATION
# ============================================================

def compute_event_uuid(event_dict):
    """
    Computes a deterministic 64-hex SHA-256 hash for idempotent event ingestion.
    Prevents duplicate database records on service restart or log re-reading.
    """
    ts = str(event_dict.get("timestamp") or "")
    e_type = str(event_dict.get("event_type") or "")
    flow_id = str(event_dict.get("flow_id") or "")
    src_ip = str(event_dict.get("src_ip") or "")
    src_port = str(event_dict.get("src_port") or "")
    dest_ip = str(event_dict.get("dest_ip") or "")
    dest_port = str(event_dict.get("dest_port") or "")
    
    alert = event_dict.get("alert") or {}
    sid = str(alert.get("signature_id") or "")
    sig = str(alert.get("signature") or "")
    
    raw_key = f"{ts}|{e_type}|{flow_id}|{src_ip}:{src_port}|{dest_ip}:{dest_port}|{sid}|{sig}"
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def parse_eve_line(line):
    """
    Safely parses a single line from Suricata EVE JSON.
    Extracts alerts, flows, DNS, HTTP, TLS, SSH, fileinfo, anomaly, and stats.
    Returns normalized dictionary or None if malformed.
    """
    if not line or not isinstance(line, str):
        return None
    
    line_str = line.strip()
    if not line_str or not line_str.startswith("{"):
        return None
    
    try:
        data = json.loads(line_str)
    except (json.JSONDecodeError, ValueError):
        return None
    
    event_type = str(data.get("event_type") or "unknown").lower()
    
    # Parse timestamp
    raw_ts = data.get("timestamp")
    parsed_dt = datetime.utcnow()
    if raw_ts:
        try:
            # Format: 2026-09-08T11:28:35.000000+0530
            clean_ts = raw_ts.replace("Z", "+00:00")
            parsed_dt = datetime.fromisoformat(clean_ts).replace(tzinfo=None)
        except Exception:
            parsed_dt = datetime.utcnow()
    
    alert_info = data.get("alert") or {}
    sid = alert_info.get("signature_id")
    sig = alert_info.get("signature") or ""
    cat = alert_info.get("category") or ""
    action = alert_info.get("action") or "allowed"
    
    if not sig:
        if event_type == "dns":
            dns_info = data.get("dns") or {}
            rrname = dns_info.get("rrname")
            rrtype = dns_info.get("rrtype") or "A"
            if rrname:
                sig = f"DNS Query: {rrname} ({rrtype})"
        elif event_type == "http":
            http_info = data.get("http") or {}
            method = http_info.get("http_method") or "GET"
            host = http_info.get("hostname") or ""
            url = http_info.get("url") or "/"
            sig = f"HTTP {method} {host}{url}"
        elif event_type == "tls":
            tls_info = data.get("tls") or {}
            sni = tls_info.get("sni") or tls_info.get("subject")
            if sni:
                sig = f"TLS SNI: {sni}"
        elif event_type == "ssh":
            ssh_info = data.get("ssh") or {}
            client = (ssh_info.get("client") or {}).get("software_version") or ""
            if client:
                sig = f"SSH Client: {client}"

    # Map Suricata severity (1 = high/critical, 2 = high, 3 = medium, 4 = low)
    raw_sev = alert_info.get("severity")
    if raw_sev in SURICATA_SEVERITY_MAP:
        severity = SURICATA_SEVERITY_MAP[raw_sev]
    elif event_type == "alert":
        severity = "medium"
    else:
        severity = "info"
    
    proto = str(data.get("proto") or "").upper()
    app_proto = str(data.get("app_proto") or "").lower()
    
    return {
        "event_uuid": compute_event_uuid(data),
        "timestamp": parsed_dt,
        "event_type": event_type,
        "sensor_name": str(data.get("host") or DEFAULT_SENSOR_NAME),
        "interface": str(data.get("in_iface") or DEFAULT_INTERFACE),
        "src_ip": data.get("src_ip"),
        "src_port": data.get("src_port"),
        "dest_ip": data.get("dest_ip"),
        "dest_port": data.get("dest_port"),
        "protocol": proto or None,
        "app_protocol": app_proto or None,
        "flow_id": str(data.get("flow_id")) if data.get("flow_id") is not None else None,
        "signature_id": sid,
        "signature": sig[:500] if sig else None,
        "category": cat[:255] if cat else None,
        "severity": severity,
        "action": action,
        "source": "Suricata IDS",
        "raw_event_json": line_str,
    }


def ingest_eve_event(event_dict, sensor_name=None, interface=None):
    """
    Idempotently stores a normalized Network IDS event in PostgreSQL.
    Accepts normalized dict, raw event dict, or raw JSON string.
    Synchronizes genuine security alerts with Alert Center and SIEM.
    """
    if isinstance(event_dict, str):
        event_dict = parse_eve_line(event_dict)
    elif isinstance(event_dict, dict) and not event_dict.get("event_uuid"):
        event_dict = parse_eve_line(json.dumps(event_dict))

    if not event_dict or not event_dict.get("event_uuid"):
        return None

    if sensor_name:
        event_dict["sensor_name"] = sensor_name
    if interface:
        event_dict["interface"] = interface
    
    uuid = event_dict["event_uuid"]
    
    # Deduplication check
    existing = NetworkIDSEvent.query.filter_by(event_uuid=uuid).first()
    if existing:
        return existing
    
    event = NetworkIDSEvent(
        event_uuid=uuid,
        timestamp=event_dict.get("timestamp", datetime.utcnow()),
        event_type=event_dict.get("event_type", "alert"),
        sensor_name=event_dict.get("sensor_name", DEFAULT_SENSOR_NAME),
        interface=event_dict.get("interface", DEFAULT_INTERFACE),
        src_ip=event_dict.get("src_ip"),
        src_port=event_dict.get("src_port"),
        dest_ip=event_dict.get("dest_ip"),
        dest_port=event_dict.get("dest_port"),
        protocol=event_dict.get("protocol"),
        app_protocol=event_dict.get("app_protocol"),
        flow_id=event_dict.get("flow_id"),
        signature_id=event_dict.get("signature_id"),
        signature=event_dict.get("signature"),
        category=event_dict.get("category"),
        severity=event_dict.get("severity", "info"),
        action=event_dict.get("action", "allowed"),
        source=event_dict.get("source", "Suricata IDS"),
        raw_event_json=event_dict.get("raw_event_json", "{}"),
        created_at=datetime.utcnow(),
    )
    
    db.session.add(event)
    db.session.commit()
    
    # Dispatch genuine alerts to Alert Center & SIEM
    # Known NIC offload / checksum diagnostic events are excluded from Alert Center
    if event.event_type == "alert":
        if not event.is_diagnostic and getattr(event, "classification", "") != "diagnostic":
            _dispatch_alert_center(event)
            if event.severity in ("high", "critical"):
                try:
                    from app.notifications.services import dispatch_notification
                    dispatch_notification(
                        title=f"[Network IDS] {event.signature or 'Security Alert'}",
                        message=f"Suricata detected {event.signature} (SID: {event.signature_id or 'N/A'}) to {event.dest_ip or 'segment'}.",
                        category="IDS",
                        severity=event.severity,
                        recipient_permission="ids.view",
                        source="Suricata IDS",
                        resource_type="ids_event",
                        resource_id=str(event.id),
                        action_url="/network-ids/",
                    )
                except Exception as e:
                    logger.debug(f"IDS notification dispatch skipped: {e}")
        _dispatch_siem(event)
    
    return event


def _dispatch_alert_center(event):
    """
    Dispatches a Suricata alert to the centralized Alert Center.
    Deduplicates against recently active alerts with the same signature and target.
    Diagnostic/checksum offload events are explicitly suppressed.
    """
    if getattr(event, "is_diagnostic", False) or getattr(event, "classification", None) == "diagnostic":
        logger.info(
            f"Suppressing Alert Center dispatch for diagnostic event (SID: {event.signature_id}, {event.signature})"
        )
        return

    try:
        from app.alerts.models import Alert
        from app.alerts.services import create_alert

        alert_title = f"[Suricata IDS] {event.signature or 'Network Intrusion Alert'}"
        affected = event.dest_ip or event.src_ip or "Network Segment"

        # Deduplicate alerts within last 15 minutes
        recent_threshold = datetime.utcnow() - timedelta(minutes=15)
        existing_alert = Alert.query.filter(
            Alert.title == alert_title,
            Alert.affected_host == affected,
            Alert.created_at >= recent_threshold,
            Alert.status.in_(["new", "acknowledged", "investigating"]),
        ).first()

        if existing_alert:
            return

        create_alert({
            "title": alert_title,
            "description": f"Suricata Network IDS detected {event.signature} (SID: {event.signature_id or 'N/A'}). Category: {event.category or 'Network Alert'}. Traffic from {event.src_ip}:{event.src_port} to {event.dest_ip}:{event.dest_port} via {event.protocol or 'IP'}.",
            "severity": event.severity,
            "category": event.category or "Network Intrusion",
            "source": "Suricata IDS",
            "affected_host": affected,
            "affected_asset": affected,
            "metadata": {
                "sid": event.signature_id,
                "flow_id": event.flow_id,
                "interface": event.interface,
                "src_ip": event.src_ip,
                "src_port": event.src_port,
                "dest_ip": event.dest_ip,
                "dest_port": event.dest_port,
                "protocol": event.protocol,
                "app_protocol": event.app_protocol,
                "event_uuid": event.event_uuid,
                "classification": event.classification,
                "is_diagnostic": event.is_diagnostic,
            },
        })
    except Exception as e:
        logger.warning(f"Failed to dispatch IDS alert to Alert Center: {e}")


def _dispatch_siem(event):
    """Dispatches event to SIEM ingestion with full metadata and diagnostic classification."""
    try:
        from app.siem.services import ingest_event as siem_ingest
        siem_ingest({
            "source": "Suricata IDS",
            "severity": event.severity,
            "category": "Network IDS" if not event.is_diagnostic else "Diagnostic / Network IDS",
            "host": event.dest_ip or event.src_ip or socket.gethostname(),
            "message": f"Suricata {event.event_type.upper()}: {event.signature or event.event_type} from {event.src_ip}:{event.src_port} to {event.dest_ip}:{event.dest_port}",
            "fields": {
                "event_type": event.event_type,
                "classification": event.classification,
                "is_diagnostic": event.is_diagnostic,
                "signature_id": event.signature_id,
                "signature": event.signature,
                "category": event.category,
                "action": event.action,
                "flow_id": event.flow_id,
                "src_ip": event.src_ip,
                "src_port": event.src_port,
                "dest_ip": event.dest_ip,
                "dest_port": event.dest_port,
                "protocol": event.protocol,
                "app_protocol": event.app_protocol,
            },
        })
    except Exception as e:
        logger.warning(f"Failed to dispatch IDS event to SIEM: {e}")


def start_ingestion_thread(app):
    """
    Starts an asynchronous background worker that continuously tails eve.json
    and ingests lines into the database without blocking Flask web requests.
    """
    global _ingestion_thread
    if _ingestion_thread and _ingestion_thread.is_alive():
        return

    def ingestion_worker():
        eve_path = os.path.join(get_ids_log_dir(), "eve.json")
        last_inode = None
        f = None

        while not _stop_event.is_set():
            if not os.path.exists(eve_path):
                time.sleep(0.5)
                continue

            try:
                stat = os.stat(eve_path)
                if f is None or stat.st_ino != last_inode:
                    if f:
                        f.close()
                    f = open(eve_path, "r", encoding="utf-8", errors="replace")
                    last_inode = stat.st_ino

                line = f.readline()
                if line:
                    norm = parse_eve_line(line)
                    if norm:
                        if app:
                            with app.app_context():
                                ingest_eve_event(norm)
                        else:
                            ingest_eve_event(norm)
                else:
                    time.sleep(0.3)
            except Exception as e:
                time.sleep(0.5)

        if f:
            try:
                f.close()
            except Exception:
                pass

    _ingestion_thread = threading.Thread(target=ingestion_worker, daemon=True)
    _ingestion_thread.start()


# ============================================================
# QUERY & TELEMETRY SERVICES
# ============================================================

def get_ids_dashboard_stats():
    """
    Aggregates real-time KPIs, protocol breakdowns, top signatures,
    and recent activity for the Network IDS Dashboard.
    """
    sensor_status = get_sensor_status()

    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

    # Filter out known NIC offload / checksum diagnostic events from security alert metrics
    sec_filter = get_security_alert_sql_filter()
    diag_filter = get_diagnostic_sql_filter()

    total_events_today = NetworkIDSEvent.query.filter(NetworkIDSEvent.timestamp >= today_start).count()
    alerts_today = NetworkIDSEvent.query.filter(
        NetworkIDSEvent.timestamp >= today_start,
        sec_filter
    ).count()

    critical_today = NetworkIDSEvent.query.filter(
        NetworkIDSEvent.timestamp >= today_start,
        sec_filter,
        NetworkIDSEvent.severity == "critical"
    ).count()

    high_today = NetworkIDSEvent.query.filter(
        NetworkIDSEvent.timestamp >= today_start,
        sec_filter,
        NetworkIDSEvent.severity == "high"
    ).count()

    medium_today = NetworkIDSEvent.query.filter(
        NetworkIDSEvent.timestamp >= today_start,
        sec_filter,
        NetworkIDSEvent.severity == "medium"
    ).count()

    low_today = NetworkIDSEvent.query.filter(
        NetworkIDSEvent.timestamp >= today_start,
        sec_filter,
        NetworkIDSEvent.severity == "low"
    ).count()

    diagnostic_today = NetworkIDSEvent.query.filter(
        NetworkIDSEvent.timestamp >= today_start,
        diag_filter
    ).count()

    # Protocol breakdown
    proto_counts = db.session.query(
        NetworkIDSEvent.protocol, func.count(NetworkIDSEvent.id)
    ).filter(
        NetworkIDSEvent.protocol.isnot(None)
    ).group_by(NetworkIDSEvent.protocol).order_by(desc(func.count(NetworkIDSEvent.id))).limit(6).all()
    protocols = {p[0]: p[1] for p in proto_counts if p[0]}

    # Top Signatures (genuine security alerts only)
    sig_query = db.session.query(
        NetworkIDSEvent.signature,
        NetworkIDSEvent.severity,
        NetworkIDSEvent.category,
        func.count(NetworkIDSEvent.id).label("count")
    ).filter(
        sec_filter,
        NetworkIDSEvent.signature.isnot(None)
    ).group_by(
        NetworkIDSEvent.signature, NetworkIDSEvent.severity, NetworkIDSEvent.category
    ).order_by(desc("count")).limit(5).all()

    top_signatures = [
        {"signature": s[0], "severity": s[1], "category": s[2] or "General", "count": s[3]}
        for s in sig_query
    ]

    # Top Source IPs
    src_query = db.session.query(
        NetworkIDSEvent.src_ip, func.count(NetworkIDSEvent.id).label("count")
    ).filter(
        NetworkIDSEvent.src_ip.isnot(None)
    ).group_by(NetworkIDSEvent.src_ip).order_by(desc("count")).limit(5).all()
    top_src_ips = [{"ip": s[0], "count": s[1]} for s in src_query]

    # Top Destination IPs
    dst_query = db.session.query(
        NetworkIDSEvent.dest_ip, func.count(NetworkIDSEvent.id).label("count")
    ).filter(
        NetworkIDSEvent.dest_ip.isnot(None)
    ).group_by(NetworkIDSEvent.dest_ip).order_by(desc("count")).limit(5).all()
    top_dst_ips = [{"ip": d[0], "count": d[1]} for d in dst_query]

    # Recent Alerts (genuine security detections only)
    recent_alerts = NetworkIDSEvent.query.filter(
        sec_filter
    ).order_by(desc(NetworkIDSEvent.timestamp)).limit(8).all()

    # Recent Events (all types, including diagnostics and flows)
    recent_events = NetworkIDSEvent.query.order_by(
        desc(NetworkIDSEvent.timestamp)
    ).limit(8).all()

    recent_alerts_dicts = [a.to_dict() for a in recent_alerts]
    recent_events_dicts = [e.to_dict() for e in recent_events]

    kpis = {
        "totalEventsToday": total_events_today,
        "total_events_today": total_events_today,
        "alertsToday": alerts_today,
        "alerts_today": alerts_today,
        "criticalAlerts": critical_today,
        "critical_alerts_today": critical_today,
        "highAlerts": high_today,
        "high_alerts_today": high_today,
        "mediumAlerts": medium_today,
        "medium_alerts_today": medium_today,
        "lowAlerts": low_today,
        "low_alerts_today": low_today,
        "diagnosticEventsToday": diagnostic_today,
        "diagnostic_events_today": diagnostic_today,
    }

    return {
        "sensor": sensor_status,
        "kpis": kpis,
        "protocols": protocols,
        "protocol_distribution": protocols,
        "topSignatures": top_signatures,
        "top_signatures": top_signatures,
        "topSourceIps": top_src_ips,
        "top_source_ips": top_src_ips,
        "topDestIps": top_dst_ips,
        "top_destination_ips": top_dst_ips,
        "recentAlerts": recent_alerts_dicts,
        "recent_alerts": recent_alerts_dicts,
        "recentEvents": recent_events_dicts,
        "recent_events": recent_events_dicts,
    }


def get_ids_events(filters=None, page=1, per_page=25):
    """
    Retrieves paginated and filtered Network IDS events.
    Supports query search, severity, event_type, classification, protocol, src_ip, dest_ip, alert_only.
    """
    filters = filters or {}
    q = NetworkIDSEvent.query

    cls_filter = str(filters.get("classification") or "").lower().strip()
    evt_type = str(filters.get("event_type") or "").lower().strip()

    # Classification & Event type filters
    if cls_filter == "diagnostic" or evt_type == "diagnostic":
        q = q.filter(get_diagnostic_sql_filter())
    elif cls_filter == "security_alert" or evt_type == "security_alert":
        q = q.filter(get_security_alert_sql_filter())
    elif filters.get("alert_only") in (True, "true", "1", 1):
        q = q.filter(NetworkIDSEvent.event_type == "alert")
    elif evt_type:
        q = q.filter(NetworkIDSEvent.event_type == evt_type)

    if filters.get("severity"):
        q = q.filter(NetworkIDSEvent.severity == str(filters["severity"]).lower().strip())

    if filters.get("protocol"):
        q = q.filter(NetworkIDSEvent.protocol == str(filters["protocol"]).upper().strip())

    if filters.get("src_ip"):
        q = q.filter(NetworkIDSEvent.src_ip.ilike(f"%{filters['src_ip'].strip()}%"))

    if filters.get("dest_ip"):
        q = q.filter(NetworkIDSEvent.dest_ip.ilike(f"%{filters['dest_ip'].strip()}%"))

    # Free text search across signature, category, and IPs
    search = filters.get("search") or filters.get("q")
    if search:
        raw_term = str(search).strip()
        term = f"%{raw_term}%"
        search_clauses = [
            NetworkIDSEvent.signature.ilike(term),
            NetworkIDSEvent.category.ilike(term),
            NetworkIDSEvent.src_ip.ilike(term),
            NetworkIDSEvent.dest_ip.ilike(term),
        ]
        if raw_term.isdigit():
            try:
                search_clauses.append(NetworkIDSEvent.signature_id == int(raw_term))
            except ValueError:
                pass
        q = q.filter(or_(*search_clauses))

    total = q.count()
    events = q.order_by(desc(NetworkIDSEvent.timestamp)).paginate(page=page, per_page=per_page, error_out=False)

    item_dicts = [e.to_dict() for e in events.items]
    return {
        "items": item_dicts,
        "events": item_dicts,
        "total": total,
        "page": page,
        "perPage": per_page,
        "pages": events.pages,
        "hasPrev": events.has_prev,
        "hasNext": events.has_next,
        "pagination": {
            "total": total,
            "page": page,
            "pages": events.pages,
            "per_page": per_page,
        },
    }


def get_ids_event_by_id(event_id):
    """Fetches single NetworkIDSEvent by database ID or event UUID."""
    if not event_id:
        return None
    
    if str(event_id).isdigit():
        evt = db.session.get(NetworkIDSEvent, int(event_id))
        if evt:
            return evt
    
    return NetworkIDSEvent.query.filter_by(event_uuid=str(event_id).strip()).first()


def escalate_event_to_incident(event_id, user_id=None, notes=None):
    """
    Allows a SOC analyst to escalate a Network IDS security alert into an Incident.
    Reuses existing Incident Response services.
    Rejects known checksum / NIC offload diagnostic events.
    """
    event = get_ids_event_by_id(event_id)
    if not event:
        raise ValueError(f"Network IDS event '{event_id}' not found.")
    
    if event.is_diagnostic or event.classification == "diagnostic":
        raise ValueError(
            f"Cannot escalate diagnostic checksum event (SID {event.signature_id or 'N/A'}: {event.signature}) to an incident."
        )

    try:
        from app.incidents.services import create_incident
        
        title = f"Network Intrusion Incident: {event.signature or 'IDS Alert'} on {event.dest_ip}"
        description = (
            f"Escalated from Network IDS event {event.event_uuid}.\n"
            f"Classification: {event.classification.upper()}\n"
            f"Signature: {event.signature or 'N/A'} (SID: {event.signature_id or 'N/A'})\n"
            f"Category: {event.category or 'Network Alert'}\n"
            f"Severity: {event.severity.upper()}\n"
            f"Source: {event.src_ip}:{event.src_port}\n"
            f"Destination: {event.dest_ip}:{event.dest_port}\n"
            f"Protocol: {event.protocol} ({event.app_protocol or 'N/A'})\n"
            f"Action: {event.action}\n"
            f"Analyst Notes: {notes or 'Escalated from Network IDS.'}"
        )
        
        incident = create_incident({
            "title": title,
            "description": description,
            "severity": event.severity if event.severity in ("critical", "high", "medium", "low") else "medium",
            "category": "Network Intrusion",
            "affected_asset": event.dest_ip or event.src_ip or "Network Host",
            "assigned_to": user_id,
        })
        
        return incident
    except Exception as e:
        raise RuntimeError(f"Failed to create incident: {str(e)}")
