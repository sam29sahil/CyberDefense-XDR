"""
CyberDefense XDR
Vulnerability Scanner & Scan History Service Layer
Provides multi-tool vulnerability assessment integrating Nmap, Nikto, WhatWeb,
Nuclei, and testssl.sh with target normalization, safe DNS resolution,
finding deduplication, CVE enrichment, Threat Intelligence correlation,
Alert Center integration, and background execution.
"""

import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from sqlalchemy import or_, desc, asc

from app.extensions import db
from app.scanner.models import Scan, VulnerabilityFinding, ScanTarget, ServiceObservation


# ============================================================
# IDENTIFIER GENERATORS
# ============================================================

def generate_scan_id():
    """Generates a unique SCAN-XXXX identifier."""
    while True:
        num = secrets.randbelow(9000) + 1000
        scan_id = f"SCAN-{num}"
        if not Scan.query.filter_by(scan_id=scan_id).first():
            return scan_id


def generate_vuln_id():
    """Generates a unique VULN-XXXX identifier."""
    while True:
        num = secrets.randbelow(9000) + 1000
        vuln_id = f"VULN-{num}"
        if not VulnerabilityFinding.query.filter_by(finding_id=vuln_id).first():
            return vuln_id


def generate_target_id():
    """Generates a unique TGT-XXX identifier."""
    while True:
        num = secrets.randbelow(900) + 100
        target_id = f"TGT-{num}"
        if not ScanTarget.query.filter_by(target_id=target_id).first():
            return target_id


# ============================================================
# TOOL AVAILABILITY CHECKER
# ============================================================

def get_available_tools():
    """
    Detects availability and version of scanner tools on the host system.
    Supports Nmap (core engine), Nikto, WhatWeb, Nuclei, and testssl.sh.
    Returns: dict mapping tool name to status and details.
    """
    tools = {}

    # 1. Nmap (core engine)
    nmap_path = shutil.which("nmap")
    if nmap_path:
        ver = "installed"
        try:
            p = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=3, shell=False)
            m = re.search(r"Nmap version ([0-9.]+)", p.stdout)
            if m:
                ver = m.group(1)
        except Exception:
            pass
        tools["nmap"] = {"available": True, "path": nmap_path, "version": ver, "required": True}
    else:
        tools["nmap"] = {"available": False, "path": None, "version": None, "required": True, "message": "Nmap is not installed."}

    # 2. Nikto
    nikto_path = shutil.which("nikto")
    if nikto_path:
        ver = "installed"
        try:
            p = subprocess.run(["nikto", "-Version"], capture_output=True, text=True, timeout=3, shell=False)
            m = re.search(r"Nikto\s+([0-9.]+)", p.stdout)
            if m:
                ver = m.group(1)
        except Exception:
            pass
        tools["nikto"] = {"available": True, "path": nikto_path, "version": ver, "required": False}
    else:
        tools["nikto"] = {"available": False, "path": None, "version": None, "required": False, "message": "Nikto is not installed"}

    # 3. WhatWeb
    whatweb_path = shutil.which("whatweb")
    if whatweb_path:
        ver = "installed"
        try:
            p = subprocess.run(["whatweb", "--version"], capture_output=True, text=True, timeout=3, shell=False)
            m = re.search(r"version\s+([0-9.]+)", p.stdout, re.IGNORECASE)
            if m:
                ver = m.group(1)
        except Exception:
            pass
        tools["whatweb"] = {"available": True, "path": whatweb_path, "version": ver, "required": False}
    else:
        tools["whatweb"] = {"available": False, "path": None, "version": None, "required": False, "message": "WhatWeb is not installed"}

    # 4. Nuclei
    nuclei_path = shutil.which("nuclei")
    if nuclei_path:
        ver = "installed"
        try:
            p = subprocess.run(["nuclei", "-version"], capture_output=True, text=True, timeout=3, shell=False)
            m = re.search(r"version\s+v?([0-9.]+)", p.stdout, re.IGNORECASE)
            if m:
                ver = m.group(1)
        except Exception:
            pass
        tools["nuclei"] = {"available": True, "path": nuclei_path, "version": ver, "required": False}
    else:
        tools["nuclei"] = {"available": False, "path": None, "version": None, "required": False, "message": "Nuclei is not installed"}

    # 5. testssl.sh
    testssl_path = shutil.which("testssl.sh") or shutil.which("testssl")
    if testssl_path:
        tools["testssl"] = {"available": True, "path": testssl_path, "version": "installed", "required": False}
    else:
        tools["testssl"] = {"available": False, "path": None, "version": None, "required": False, "message": "testssl.sh is not installed"}

    return tools


# ============================================================
# TARGET VALIDATION & NORMALIZATION (PHASE 2 & PHASE 3)
# ============================================================

# Dangerous shell injection characters
FORBIDDEN_SHELL_CHARS = re.compile(r"[;&|`$><\"'\\\[\]{}()!]")
VALID_HOSTNAME_PATTERN = re.compile(
    r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$"
)


def normalize_and_validate_target(target_str):
    """
    Normalizes and validates target strings across 7 supported types:
    1. IPv4 (loopback, RFC 1918, or authorized target)
    2. IPv6 (e.g. ::1, 2001:db8::1)
    3. Hostname (e.g. server.local, dev.lan)
    4. Domain (e.g. example.com)
    5. CIDR / Subnet (e.g. 192.168.1.0/24, safe max /24)
    6. HTTP URL (e.g. http://127.0.0.1:5000/path)
    7. HTTPS URL (e.g. https://example.com)

    Returns: (is_valid: bool, target_info: dict, error_message: str)
    """
    if not target_str or not isinstance(target_str, str):
        return False, {}, "Target cannot be empty."

    raw = target_str.strip()
    if len(raw) > 500:
        return False, {}, "Target length exceeds 500 characters."

    # Check for shell injection characters
    # Exception: allow slashes, colons, question marks, and query strings in URLs
    chars_to_check = raw
    if raw.startswith("http://") or raw.startswith("https://"):
        # Remove query and fragment for char validation
        parsed_tmp = urllib.parse.urlsplit(raw)
        chars_to_check = f"{parsed_tmp.netloc}{parsed_tmp.path}"

    if FORBIDDEN_SHELL_CHARS.search(chars_to_check):
        return False, {}, "Target contains illegal characters or command injection syntax."

    # 1. URL Target (HTTP / HTTPS)
    if raw.startswith("http://") or raw.startswith("https://"):
        try:
            parsed = urllib.parse.urlsplit(raw)
            scheme = parsed.scheme.lower()
            if scheme not in ("http", "https"):
                return False, {}, "Only HTTP and HTTPS URL schemes are supported."

            hostname = parsed.hostname
            if not hostname:
                return False, {}, "URL must contain a valid hostname or IP address."

            port = parsed.port or (443 if scheme == "https" else 80)
            path = parsed.path or "/"

            # Validate the host portion of URL
            is_host_valid, host_info, host_err = normalize_and_validate_target(hostname)
            if not is_host_valid:
                return False, {}, f"Invalid URL host '{hostname}': {host_err}"

            normalized = f"{scheme}://{hostname}:{port}{path}"
            return True, {
                "original": raw,
                "target_type": "url",
                "normalized": normalized,
                "scheme": scheme,
                "host": hostname,
                "port": port,
                "path": path,
                "is_authorized": True,
            }, ""
        except Exception as e:
            return False, {}, f"Failed to parse URL target: {str(e)}"

    # 2. CIDR / Subnet
    if "/" in raw:
        try:
            net = ipaddress.ip_network(raw, strict=False)
            if net.version == 4 and net.prefixlen < 24:
                return False, {}, f"CIDR subnet /{net.prefixlen} is too large. Maximum allowed scope is /24 for safety."
            if net.version == 6 and net.prefixlen < 112:
                return False, {}, f"IPv6 CIDR subnet /{net.prefixlen} is too large."

            return True, {
                "original": raw,
                "target_type": "cidr",
                "normalized": str(net),
                "host": str(net.network_address),
                "network": str(net),
                "is_authorized": True,
            }, ""
        except ValueError as ve:
            return False, {}, f"Invalid CIDR network format: {str(ve)}"

    # 3. IPv4 / IPv6 Address
    try:
        ip = ipaddress.ip_address(raw)
        t_type = "ipv4" if ip.version == 4 else "ipv6"
        return True, {
            "original": raw,
            "target_type": t_type,
            "normalized": str(ip),
            "host": str(ip),
            "is_authorized": True,
        }, ""
    except ValueError:
        pass

    # 4. Hostname / Domain
    # Remove trailing dot if present
    clean_host = raw.rstrip(".")
    if not VALID_HOSTNAME_PATTERN.match(clean_host):
        # Check if matches an existing configured ScanTarget name
        matched_target = ScanTarget.query.filter(
            or_(
                ScanTarget.name.ilike(raw),
                ScanTarget.target_value.ilike(raw),
            )
        ).first()
        if matched_target:
            return normalize_and_validate_target(matched_target.target_value)
        return False, {}, f"Invalid hostname or domain format: '{raw}'."

    lower_host = clean_host.lower()
    is_domain = "." in clean_host and not (clean_host.endswith(".local") or clean_host.endswith(".lan") or clean_host.endswith(".lab") or clean_host.endswith(".test"))
    t_type = "domain" if is_domain else "hostname"

    return True, {
        "original": raw,
        "target_type": t_type,
        "normalized": lower_host,
        "host": lower_host,
        "is_authorized": True,
    }, ""


def validate_target(target_str):
    """
    Backward-compatible target validator returning (is_valid: bool, target_or_error: str).
    """
    is_val, info, err = normalize_and_validate_target(target_str)
    if is_val:
        return True, info.get("normalized", target_str.strip())
    return False, err


def resolve_target_dns(host):
    """
    Safely resolves IPv4 and IPv6 addresses for hostname/domain targets.
    Handles DNS failures, timeouts, and multiple addresses gracefully.
    Returns: dict with resolved IPs and timestamp.
    """
    clean_host = host.strip().lower()
    if clean_host.startswith("http://") or clean_host.startswith("https://"):
        clean_host = urllib.parse.urlsplit(clean_host).hostname or clean_host

    result = {
        "host": clean_host,
        "ipv4": [],
        "ipv6": [],
        "resolved_at": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": "unresolved",
        "error": None,
    }

    # If it is already a literal IP address, record directly
    try:
        ip = ipaddress.ip_address(clean_host)
        if ip.version == 4:
            result["ipv4"].append(str(ip))
        else:
            result["ipv6"].append(str(ip))
        result["status"] = "resolved"
        return result
    except ValueError:
        pass

    try:
        # Set temporary socket default timeout for safe resolution
        orig_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(4.0)
        try:
            addr_info = socket.getaddrinfo(clean_host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            ipv4_set = set()
            ipv6_set = set()
            for family, socktype, proto, canonname, sockaddr in addr_info:
                ip_addr = sockaddr[0]
                if family == socket.AF_INET:
                    ipv4_set.add(ip_addr)
                elif family == socket.AF_INET6:
                    ipv6_set.add(ip_addr)
            result["ipv4"] = sorted(list(ipv4_set))
            result["ipv6"] = sorted(list(ipv6_set))
            result["status"] = "resolved" if (result["ipv4"] or result["ipv6"]) else "no_records"
        finally:
            socket.setdefaulttimeout(orig_timeout)
    except socket.gaierror as ge:
        result["status"] = "failed"
        result["error"] = f"DNS resolution failed: {str(ge)}"
    except Exception as e:
        result["status"] = "failed"
        result["error"] = f"DNS error: {str(e)}"

    return result


# ============================================================
# SAFE NMAP EXECUTION (PHASE 4)
# ============================================================

def build_nmap_command(target, scan_type="Quick Scan", profile="STANDARD", options=None):
    """
    Constructs safe Nmap command arguments as a list (shell=False).
    Uses unprivileged TCP Connect (-sT) so sudo is not required.
    Outputs structured XML directly to stdout (-oX -).
    """
    options = options or {}
    cmd = ["nmap", "-sT", "-T4", "-oX", "-"]

    prof = (profile or scan_type or "STANDARD").upper()

    if prof in ("QUICK", "QUICK SCAN"):
        cmd.extend(["--top-ports", "100"])
    elif prof in ("WEB", "WEB APPLICATION SCAN", "WEB SCAN"):
        cmd.extend(["-sV", "--version-light", "-p", "80,443,8080,8443,3000,5000,8000,8888,9000,9443"])
    elif prof in ("DEEP", "FULL", "FULL SCAN", "DEEP SCAN"):
        cmd.extend(["-sV", "--version-all", "--top-ports", "1000"])
    elif prof in ("COMPLIANCE", "COMPLIANCE SCAN"):
        cmd.extend(["-sV", "-p", "21,22,23,25,80,110,139,443,445,1433,3306,3389,5432,8080"])
    else:
        # Standard Profile
        cmd.extend(["-sV", "--version-light", "--top-ports", "500"])

    # Safe scripts if requested
    if options.get("safe_checks", True):
        cmd.extend(["--script", "banner"])

    cmd.append(target)
    return cmd


def execute_nmap(target, scan_type="Quick Scan", profile="STANDARD", options=None, timeout=180):
    """
    Executes Nmap safely using subprocess.run(shell=False).
    Captures stdout (XML) and stderr.
    """
    cmd = build_nmap_command(target, scan_type=scan_type, profile=profile, options=options)

    try:
        result = subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if result.returncode == 0:
            return True, result.stdout, ""
        else:
            return False, result.stdout, f"Nmap exited with code {result.returncode}: {result.stderr.strip()}"

    except subprocess.TimeoutExpired:
        return False, "", f"Nmap scan timed out after {timeout} seconds on target '{target}'."
    except FileNotFoundError:
        return False, "", "Nmap binary was not found on the system. Please ensure /usr/bin/nmap is installed."
    except Exception as e:
        return False, "", f"Execution error running Nmap: {str(e)}"


def parse_nmap_xml(xml_content, default_host="localhost"):
    """
    Parses Nmap XML output (-oX -) using standard ElementTree.
    Extracts open ports, services, versions, and CPEs.
    """
    if not xml_content or not xml_content.strip():
        return []

    results = []
    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        return []

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        if status_el is not None and status_el.get("state") == "down":
            continue

        addr_el = host_el.find("address")
        host_addr = addr_el.get("addr") if addr_el is not None else default_host

        hostname = host_addr
        hostnames_el = host_el.find("hostnames")
        if hostnames_el is not None:
            first_h = hostnames_el.find("hostname")
            if first_h is not None and first_h.get("name"):
                hostname = first_h.get("name")

        ports_el = host_el.find("ports")
        if ports_el is None:
            continue

        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            port_id = int(port_el.get("portid", 0))
            proto = port_el.get("protocol", "tcp")

            service_name = ""
            product = ""
            version = ""
            extrainfo = ""
            cpe_list = []

            service_el = port_el.find("service")
            if service_el is not None:
                service_name = service_el.get("name", "")
                product = service_el.get("product", "")
                version = service_el.get("version", "")
                extrainfo = service_el.get("extrainfo", "")
                for cpe_el in service_el.findall("cpe"):
                    if cpe_el.text:
                        cpe_list.append(cpe_el.text)

            scripts = []
            for script_el in port_el.findall("script"):
                scripts.append({
                    "id": script_el.get("id", ""),
                    "output": script_el.get("output", ""),
                })

            results.append({
                "host": hostname,
                "ip": host_addr,
                "port": port_id,
                "protocol": proto,
                "service": service_name,
                "product": product,
                "version": version,
                "extrainfo": extrainfo,
                "cpe": cpe_list,
                "scripts": scripts,
            })

    return results


# ============================================================
# MULTI-TOOL RUNNERS (PHASES 5, 6, 7, 8)
# ============================================================

def run_whatweb_scan(target_url, timeout=45):
    """
    Executes WhatWeb to fingerprint web technologies, frameworks, and CMS.
    Does NOT mark technology detection as a vulnerability.
    Returns: list of detected technology dicts.
    """
    tools = get_available_tools()
    if not tools["whatweb"]["available"]:
        return []

    tmp_path = None
    technologies = []

    try:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            tmp_path = f.name

        cmd = ["whatweb", f"--log-json={tmp_path}", "--color=never", "-a", "1", "--quiet", target_url]
        subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=timeout)

        if os.path.exists(tmp_path) and os.path.getsize(tmp_path) > 0:
            with open(tmp_path, "r", encoding="utf-8", errors="replace") as jf:
                parsed_data = json.load(jf)

            if isinstance(parsed_data, dict):
                parsed_data = [parsed_data]

            for entry in parsed_data:
                plugins = entry.get("plugins") or {}
                for name, details in plugins.items():
                    ver_val = ""
                    cat_val = ""
                    str_item = ""
                    if isinstance(details, dict):
                        ver = details.get("version") or ""
                        ver_val = ver[0] if isinstance(ver, list) and ver else str(ver)
                        cat = details.get("module") or ""
                        cat_val = cat[0] if isinstance(cat, list) and cat else str(cat)
                        str_val = details.get("string") or ""
                        str_item = str_val[0] if isinstance(str_val, list) and str_val else str(str_val)

                    tech = {
                        "name": name,
                        "version": ver_val,
                        "category": cat_val,
                        "string": str_item,
                    }
                    technologies.append(tech)

    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass

    return technologies


def run_nikto_scan(target_url, timeout=30):
    """
    Executes Nikto for authorized web server vulnerability assessment.
    Collects misconfigurations, exposed files, and missing headers.
    Enforces non-interactive flags and bounded maxtime.
    Returns: list of normalized raw finding dicts.
    """
    tools = get_available_tools()
    if not tools["nikto"]["available"]:
        return []

    findings = []
    tmp_path = None

    try:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            tmp_path = f.name

        # Tuning: 1 (interesting files), 2 (misconfigurations), 3 (information disclosure), b (software identification)
        # maxtime safe bound (15s max to prevent long-running hanging scans)
        max_time_sec = min(15, max(5, timeout - 5))
        cmd = [
            "nikto",
            "-h", target_url,
            "-Format", "json",
            "-output", tmp_path,
            "-Tuning", "1,2,3,b",
            "-maxtime", f"{max_time_sec}s",
            "-nointeractive",
            "-ask", "no",
        ]

        subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=timeout)

        if os.path.exists(tmp_path) and os.path.getsize(tmp_path) > 0:
            with open(tmp_path, "r", encoding="utf-8", errors="replace") as jf:
                data = json.load(jf)

            vulnerabilities = data.get("vulnerabilities") or []
            host_info = data.get("host") or target_url
            port = int(data.get("port") or (443 if "https" in target_url else 80))

            for v in vulnerabilities:
                msg = v.get("msg") or ""
                if not msg:
                    continue

                # Classify severity based on message content
                lower_msg = msg.lower()
                sev = "low"
                cvss = 3.5
                if any(k in lower_msg for k in ("vulnerable", "rce", "remote code", "sql injection", "backdoor", "bypass")):
                    sev = "high"
                    cvss = 7.8
                elif any(k in lower_msg for k in ("directory indexing", "internal ip", "cookie without", "x-frame-options", "security header")):
                    sev = "medium"
                    cvss = 5.3

                findings.append({
                    "title": f"Web Server Finding: {msg[:80]}",
                    "description": msg,
                    "severity": sev,
                    "cvss_score": cvss,
                    "cve": "",
                    "cwe": "CWE-200" if "disclosure" in lower_msg else "CWE-16",
                    "remediation": "Review web server configuration and apply recommended hardening baselines.",
                    "evidence": f"Nikto URI: {v.get('url', '/')} | Method: {v.get('method', 'GET')}",
                    "tool": "nikto",
                    "confidence": "high",
                    "host": str(host_info),
                    "port": port,
                    "protocol": "tcp",
                    "service": "https" if "https" in target_url else "http",
                })

    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass

    return findings


def run_nuclei_scan(target_url, timeout=60):
    """
    Executes Nuclei for non-destructive web vulnerability template checks if installed.
    Gracefully degrades if not installed.
    Returns: list of normalized finding dicts.
    """
    tools = get_available_tools()
    if not tools["nuclei"]["available"]:
        return []

    findings = []
    cmd = [
        "nuclei",
        "-u", target_url,
        "-jsonl",
        "-silent",
        "-tags", "cve,misconfig,exposure,tech",
        "-severity", "info,low,medium,high,critical",
        "-timeout", "5",
    ]

    try:
        result = subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=timeout)
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                item = json.loads(line)
                info = item.get("info") or {}
                sev = (info.get("severity") or "low").lower()
                title = info.get("name") or item.get("template-id") or "Nuclei Security Finding"

                classification = info.get("classification") or {}
                cve_id = (classification.get("cve-id") or [""])[0] if isinstance(classification.get("cve-id"), list) else (classification.get("cve-id") or "")
                cwe_id = (classification.get("cwe-id") or [""])[0] if isinstance(classification.get("cwe-id"), list) else (classification.get("cwe-id") or "")
                cvss_score = float(classification.get("cvss-score") or (9.0 if sev == "critical" else 7.5 if sev == "high" else 5.0 if sev == "medium" else 2.5))

                findings.append({
                    "title": title,
                    "description": info.get("description") or f"Identified by Nuclei template {item.get('template-id')}",
                    "severity": sev if sev in ("critical", "high", "medium", "low") else "low",
                    "cvss_score": cvss_score,
                    "cve": cve_id or "",
                    "cwe": cwe_id or "",
                    "remediation": info.get("remediation") or "Apply patch or remediate according to template guidelines.",
                    "evidence": f"Matched URL: {item.get('matched-at', target_url)} | Template: {item.get('template-id')}",
                    "tool": "nuclei",
                    "confidence": "confirmed",
                    "host": urllib.parse.urlsplit(target_url).hostname or target_url,
                    "port": urllib.parse.urlsplit(target_url).port or (443 if "https" in target_url else 80),
                    "protocol": "tcp",
                    "service": "https" if "https" in target_url else "http",
                    "references": info.get("reference") or [],
                })
            except Exception:
                pass
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass

    return findings


def run_testssl_scan(target_host, port=443, timeout=60):
    """
    Executes testssl.sh for TLS assessment on HTTPS targets if installed.
    Gracefully degrades if not installed.
    Returns: tuple of (findings_list, tls_summary_dict).
    """
    tools = get_available_tools()
    if not tools["testssl"]["available"]:
        return [], {}

    testssl_bin = tools["testssl"]["path"]
    tmp_path = None
    findings = []
    tls_summary = {"host": target_host, "port": port}

    try:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            tmp_path = f.name

        cmd = [
            testssl_bin,
            "--jsonfile-pretty", tmp_path,
            "--fast",
            f"{target_host}:{port}",
        ]

        subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=timeout)

        if os.path.exists(tmp_path) and os.path.getsize(tmp_path) > 0:
            with open(tmp_path, "r", encoding="utf-8", errors="replace") as jf:
                data = json.load(jf)

            if isinstance(data, list):
                for item in data:
                    sev = (item.get("severity") or "OK").upper()
                    item_id = item.get("id") or ""
                    finding_text = item.get("finding") or ""

                    if sev in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
                        findings.append({
                            "title": f"TLS Security Issue: {item_id.replace('_', ' ').title()}",
                            "description": finding_text or f"Vulnerability detected by testssl on {item_id}",
                            "severity": sev.lower(),
                            "cvss_score": 7.5 if sev == "HIGH" else 5.0 if sev == "MEDIUM" else 3.0,
                            "cve": item.get("cve") or "",
                            "cwe": "CWE-310",
                            "remediation": "Disable deprecated TLS protocol versions and weak ciphers; enforce modern TLS 1.2+.",
                            "evidence": f"testssl finding: {finding_text}",
                            "tool": "testssl",
                            "confidence": "confirmed",
                            "host": target_host,
                            "port": port,
                            "protocol": "tcp",
                            "service": "https",
                        })

    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass

    return findings, tls_summary


# ============================================================
# THREAT INTELLIGENCE CORRELATION (PHASE 18)
# ============================================================

def correlate_threat_intel(indicators):
    """
    Correlates target IP, domain, or URL with existing Threat Intelligence IOCs.
    Returns: dict mapping indicator to IOC details.
    """
    matches = {}
    if not indicators:
        return matches

    try:
        from app.threatintel.models.ioc import IOC
        # Clean indicators
        clean_vals = [str(i).strip() for i in indicators if i and str(i).strip()]
        if not clean_vals:
            return matches

        ioc_records = IOC.query.filter(IOC.value.in_(clean_vals)).all()
        for ioc in ioc_records:
            matches[ioc.value] = {
                "ioc_id": ioc.ioc_id,
                "threat_level": ioc.threat_level,
                "confidence": ioc.confidence,
                "source": ioc.source or "Threat Intelligence Feed",
                "campaign": ioc.campaign_name or "N/A",
                "status": ioc.status,
            }
    except Exception:
        pass

    return matches


# ============================================================
# FINDING NORMALIZATION & DEDUPLICATION (PHASE 11 & PHASE 12)
# ============================================================

def generate_finding_fingerprint(host, port, service, title_or_cve):
    """Generates a stable 64-hex SHA-256 fingerprint for deduplication."""
    norm_host = str(host or "").strip().lower()
    norm_port = str(port or "0").strip()
    norm_key = re.sub(r"[^a-zA-Z0-9]", "", str(title_or_cve or "").lower())[:40]
    raw = f"{norm_host}:{norm_port}:{norm_key}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def deduplicate_and_merge_findings(findings_list):
    """
    Deduplicates findings from multiple tools.
    If multiple tools detect the same underlying vulnerability, merges evidence
    and takes the highest severity/CVSS score.
    """
    dedup_map = {}
    sev_weight = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    for item in findings_list:
        if isinstance(item, dict):
            f = dict(item)
        elif hasattr(item, "to_dict"):
            f = item.to_dict()
        else:
            f = {
                "host": getattr(item, "host", ""),
                "port": getattr(item, "port", None),
                "service": getattr(item, "service", ""),
                "cve": getattr(item, "cve", ""),
                "title": getattr(item, "title", ""),
                "severity": getattr(item, "severity", "low"),
                "cvss_score": getattr(item, "cvss_score", 0.0),
                "tool": getattr(item, "tool", "nmap"),
                "evidence": getattr(item, "evidence", ""),
                "fingerprint": getattr(item, "fingerprint", None),
            }

        fp = f.get("fingerprint") or generate_finding_fingerprint(
            f.get("host"), f.get("port"), f.get("service"), f.get("cve") or f.get("title")
        )
        f["fingerprint"] = fp

        if fp not in dedup_map:
            cvss = f.get("cvss_score") or f.get("cvssScore") or 0.0
            f["cvss_score"] = cvss
            f["cvssScore"] = cvss
            dedup_map[fp] = f
        else:
            existing = dedup_map[fp]
            existing_tool = existing.get("tool", "nmap")
            new_tool = f.get("tool", "heuristic")
            if new_tool not in existing_tool:
                existing["tool"] = f"{existing_tool}, {new_tool}"

            if f.get("evidence") and f["evidence"] not in existing.get("evidence", ""):
                existing["evidence"] = f"{existing.get('evidence', '')}\n[Additional Evidence from {new_tool}]: {f['evidence']}".strip()

            cvss = f.get("cvss_score") or f.get("cvssScore") or 0.0
            existing_cvss = existing.get("cvss_score") or existing.get("cvssScore") or 0.0
            if sev_weight.get(f.get("severity", "low"), 0) > sev_weight.get(existing.get("severity", "low"), 0):
                existing["severity"] = f["severity"]
                new_cvss = max(cvss, existing_cvss)
                existing["cvss_score"] = new_cvss
                existing["cvssScore"] = new_cvss
                existing["title"] = f.get("title", existing["title"])
            else:
                new_cvss = max(cvss, existing_cvss)
                existing["cvss_score"] = new_cvss
                existing["cvssScore"] = new_cvss

    return list(dedup_map.values())



# ============================================================
# NMAP HEURISTIC FINDINGS EVALUATOR
# ============================================================

def probe_http_service_for_cleartext(host, port):
    """
    Probes an HTTP endpoint with a bounded timeout (2s).
    Only returns a finding if actual HTTP response evidence shows cleartext service without HTTPS redirection.
    Returns: (is_vulnerable, finding_data_or_None)
    """
    import urllib.request
    url = f"http://{host}:{port}/"
    try:
        class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
            def http_error_301(self, req, fp, code, msg, headers):
                return fp
            def http_error_302(self, req, fp, code, msg, headers):
                return fp
            def http_error_307(self, req, fp, code, msg, headers):
                return fp
            def http_error_308(self, req, fp, code, msg, headers):
                return fp

        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "CyberDefense-XDR-Scanner/1.0"})
        opener = urllib.request.build_opener(NoRedirectHandler)
        resp = opener.open(req, timeout=2.0)
        status = getattr(resp, "status", getattr(resp, "code", 200))
        headers = {k.lower(): v for k, v in resp.headers.items()}
        location = headers.get("location", "")

        # If it redirects to HTTPS, it is properly mitigating cleartext
        if status in (301, 302, 307, 308) and location.lower().startswith("https://"):
            return False, None

        # If it returns 200 OK or non-redirect cleartext response
        if status == 200:
            evidence = f"HTTP endpoint {url} returned HTTP 200 OK without redirecting to HTTPS. Server: {headers.get('server', 'unspecified')}"
            return True, {
                "cve": "",
                "cwe": "CWE-319",
                "title": "Cleartext HTTP Web Service Without HTTPS Redirection",
                "severity": "low",
                "cvss_score": 3.7,
                "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                "description": f"HTTP service listening on port {port}/tcp is serving traffic over unencrypted transport without enforcing HTTPS redirection.",
                "remediation": "Deploy SSL/TLS certificates and configure an HTTP 301/308 redirect to enforce HTTPS.",
                "port": port,
                "protocol": "tcp",
                "service": "http",
                "product": headers.get("server", "HTTP Server"),
                "version": "",
                "evidence": evidence,
                "references": ["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"],
                "tool": "web-probe",
                "confidence": "confirmed",
                "host": host,
            }
    except Exception:
        pass

    return False, None


def probe_https_for_hsts(host, port=443):
    """
    Probes an HTTPS endpoint to verify if HSTS (Strict-Transport-Security header) is missing.
    Returns: (is_vulnerable, finding_data_or_None)
    """
    import urllib.request
    import ssl
    url = f"https://{host}:{port}/"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "CyberDefense-XDR-Scanner/1.0"})
        with urllib.request.urlopen(req, timeout=2.0, context=ctx) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            if "strict-transport-security" not in headers:
                evidence = f"HTTPS endpoint {url} responded with status {resp.status} but omitted the 'Strict-Transport-Security' header."
                return True, {
                    "cve": "",
                    "cwe": "CWE-319",
                    "title": "Missing HTTP Strict Transport Security (HSTS) Header",
                    "severity": "low",
                    "cvss_score": 3.1,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    "description": f"The HTTPS service on port {port} does not advertise HTTP Strict Transport Security (HSTS), allowing potential SSL stripping.",
                    "remediation": "Configure the 'Strict-Transport-Security: max-age=31536000; includeSubDomains' header in web server configuration.",
                    "port": port,
                    "protocol": "tcp",
                    "service": "https",
                    "product": headers.get("server", "HTTPS Server"),
                    "version": "",
                    "evidence": evidence,
                    "references": ["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"],
                    "tool": "web-probe",
                    "confidence": "confirmed",
                    "host": host,
                }
    except Exception:
        pass
    return False, None


def evaluate_findings_from_ports(scan, open_ports, target):
    """
    Evaluates discovered open ports, services, and versions.
    Separates discovered services/exposure observations from confirmed security vulnerabilities.
    - tcpwrapped and generic open ports are recorded as ServiceObservations without CVE/CWE/CVSS.
    - VulnerabilityFinding is created only for confirmed vulnerable services or cleartext exposures.
    - No placeholder/invented CVEs are assigned.
    """
    findings_created = []
    service_obs = []

    for item in open_ports:
        port = int(item["port"])
        service = (item.get("service") or "").lower()
        product = item.get("product") or ""
        version = item.get("version") or ""
        extrainfo = item.get("extrainfo") or ""
        host = item.get("host") or target
        proto = item.get("protocol", "tcp")
        state = item.get("state", "open")
        port_label = f"{port}/{proto}"

        # 0. Check tcpwrapped: strictly a service observation, NOT a vulnerability finding
        is_tcpwrapped = (
            service == "tcpwrapped"
            or "tcpwrapped" in service
            or "tcpwrapped" in product.lower()
            or state == "tcpwrapped"
        )
        if is_tcpwrapped:
            service_obs.append(
                ServiceObservation(
                    port=port,
                    protocol=proto,
                    service="tcpwrapped",
                    product=product or "tcpwrapped",
                    version=version,
                    extrainfo=extrainfo,
                    host=host,
                    state="tcpwrapped",
                    tool="nmap",
                ).to_dict()
            )
            continue

        # Record every genuine discovered port as a service observation
        service_obs.append(
            ServiceObservation(
                port=port,
                protocol=proto,
                service=service or "unknown",
                product=product,
                version=version,
                extrainfo=extrainfo,
                host=host,
                state=state,
                tool="nmap",
            ).to_dict()
        )

        # 1. Telnet (Port 23) - Cleartext interactive shell
        if port == 23 or service == "telnet":
            findings_created.append({
                "cve": "",
                "cwe": "CWE-319",
                "title": "Unencrypted Telnet Service Exposed",
                "severity": "high",
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                "description": f"Telnet daemon is actively listening on port {port_label}. Transmits all authentication and session data in cleartext.",
                "remediation": "Disable the Telnet service immediately and replace with SSH (port 22).",
                "port": port,
                "protocol": proto,
                "service": "telnet",
                "product": product or "Telnet Daemon",
                "version": version,
                "evidence": f"Active cleartext listener on {host}:{port_label}",
                "references": ["https://csrc.nist.gov/publications/detail/sp/800-123/final"],
                "tool": "nmap",
                "confidence": "confirmed",
                "host": host,
            })

        # 2. FTP (Port 21) - Cleartext credential transfer
        elif port == 21 or service == "ftp":
            findings_created.append({
                "cve": "",
                "cwe": "CWE-319",
                "title": "Cleartext FTP Service Enabled",
                "severity": "medium",
                "cvss_score": 5.3,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                "description": f"FTP daemon on port {port_label} accepts credentials in cleartext.",
                "remediation": "Enforce FTPS or migrate to SFTP (SSH File Transfer Protocol).",
                "port": port,
                "protocol": proto,
                "service": "ftp",
                "product": product or "FTP Server",
                "version": version,
                "evidence": f"FTP listening on {host}:{port_label}",
                "references": ["https://datatracker.ietf.org/doc/html/rfc2228"],
                "tool": "nmap",
                "confidence": "confirmed",
                "host": host,
            })

        # 3. SMB (Port 445 / 139) - Exposure misconfiguration (no invented CVE)
        elif port in (445, 139) or service in ("microsoft-ds", "netbios-ssn", "smb"):
            findings_created.append({
                "cve": "",
                "cwe": "CWE-284",
                "title": "SMB Service Exposed",
                "severity": "high",
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
                "description": f"Server Message Block service reachable on port {port_label}. SMB exposure poses high lateral movement risk.",
                "remediation": "Disable SMBv1, enforce SMB signing and SMBv3 encryption, restrict access with firewall.",
                "port": port,
                "protocol": proto,
                "service": "smb",
                "product": product or "Samba",
                "version": version,
                "evidence": f"SMB listener on {host}:{port_label}",
                "references": ["https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security"],
                "tool": "nmap",
                "confidence": "confirmed",
                "host": host,
            })

        # 4. RDP (Port 3389) - Exposure misconfiguration (no invented CVE)
        elif port == 3389 or service == "ms-wbt-server":
            findings_created.append({
                "cve": "",
                "cwe": "CWE-287",
                "title": "Remote Desktop Protocol (RDP) Exposed",
                "severity": "high",
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "description": f"RDP service reachable directly on port {port_label}. Remote desktop exposed without bastion or VPN.",
                "remediation": "Restrict RDP to VPN/Bastion access only; enforce Network Level Authentication (NLA) and MFA.",
                "port": port,
                "protocol": proto,
                "service": "rdp",
                "product": product or "RDP Server",
                "version": version,
                "evidence": f"RDP listening on {host}:{port_label}",
                "references": ["https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-205a"],
                "tool": "nmap",
                "confidence": "confirmed",
                "host": host,
            })

        # 5. Database Services (5432, 3306, 1433, 27017, 6379)
        elif port in (5432, 3306, 1433, 27017, 6379) or service in ("postgresql", "mysql", "ms-sql-s", "mongodb", "redis"):
            db_name = "PostgreSQL" if port == 5432 else "MySQL" if port == 3306 else "MSSQL" if port == 1433 else "Redis" if port == 6379 else "Database"
            findings_created.append({
                "cve": "",
                "cwe": "CWE-284",
                "title": f"Database Port Directly Accessible ({db_name})",
                "severity": "medium",
                "cvss_score": 5.0,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
                "description": f"{db_name} listener reachable on port {port_label}. Database ports should not be accessible from untrusted segments.",
                "remediation": f"Bind {db_name} listener to 127.0.0.1 or private interface only. Enforce TLS and strong authentication.",
                "port": port,
                "protocol": proto,
                "service": service or db_name.lower(),
                "product": product or db_name,
                "version": version,
                "evidence": f"{db_name} open on {host}:{port_label}",
                "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html"],
                "tool": "nmap",
                "confidence": "confirmed",
                "host": host,
            })

        # 6. HTTP Web Service (Port 80 / 8080) - Requires actual HTTP response evidence
        elif port in (80, 8080) or service in ("http", "http-alt"):
            is_vuln, vuln_data = probe_http_service_for_cleartext(host, port)
            if is_vuln and vuln_data:
                findings_created.append(vuln_data)

        # 7. HTTPS Web Service (Port 443 / 8443) - Check HSTS header with real evidence
        elif port in (443, 8443) or service in ("https", "https-alt", "ssl/http"):
            is_vuln, vuln_data = probe_https_for_hsts(host, port)
            if is_vuln and vuln_data:
                findings_created.append(vuln_data)

        # 8. All other open ports (e.g. SSH port 22, DNS port 53, etc.)
        # are already recorded as ServiceObservation above and do NOT create VulnerabilityFinding.

    # Update scan service observations
    current_obs = list(scan.service_observations or [])
    seen_keys = {(o.get("host"), o.get("port"), o.get("protocol")) for o in current_obs}
    for so in service_obs:
        k = (so.get("host"), so.get("port"), so.get("protocol"))
        if k not in seen_keys:
            current_obs.append(so)
            seen_keys.add(k)
    scan.service_observations = current_obs
    scan.service_observations_count = len(current_obs)

    # Deduplicate & persist vulnerability findings
    deduped = deduplicate_and_merge_findings(findings_created)
    db_findings = []

    for f_data in deduped:
        finding = VulnerabilityFinding(
            finding_id=generate_vuln_id(),
            scan_id=scan.id,
            cve=f_data.get("cve") or "",
            cwe=f_data.get("cwe") or "",
            title=f_data["title"],
            severity=f_data["severity"],
            cvss_score=f_data["cvss_score"],
            cvss_vector=f_data.get("cvss_vector", ""),
            description=f_data["description"],
            remediation=f_data["remediation"],
            host=f_data["host"],
            port=f_data.get("port"),
            protocol=f_data.get("protocol", "tcp"),
            service=f_data.get("service", ""),
            product=f_data.get("product", ""),
            version=f_data.get("version", ""),
            evidence=f_data.get("evidence", ""),
            tool=f_data.get("tool", "nmap"),
            confidence=f_data.get("confidence", "confirmed"),
            fingerprint=f_data.get("fingerprint"),
            threat_intel_json=json.dumps(f_data.get("threat_intel") or {}),
            affected_assets_json=json.dumps([f_data["host"]]),
            references_json=json.dumps(f_data.get("references") or []),
            status="open",
            published_date=datetime.utcnow().strftime("%Y-%m-%d"),
            discovered_at=datetime.utcnow(),
        )
        db.session.add(finding)
        db_findings.append(finding)

    # Compute risk score
    crit = sum(1 for f in db_findings if f.severity == "critical")
    high = sum(1 for f in db_findings if f.severity == "high")
    med = sum(1 for f in db_findings if f.severity == "medium")
    low = sum(1 for f in db_findings if f.severity == "low")
    risk_score = min(99, int(crit * 25 + high * 15 + med * 6 + low * 2))

    scan.total_findings = len(db_findings)
    scan.critical_count = crit
    scan.high_count = high
    scan.medium_count = med
    scan.low_count = low
    scan.risk_score = risk_score

    db.session.commit()
    integrate_alert_center(scan, db_findings)
    return db_findings


# ============================================================
# ALERT CENTER INTEGRATION (PHASE 17)
# ============================================================

def integrate_alert_center(scan, findings):
    """
    Creates security alerts in Alert Center for critical or high vulnerability findings.
    Prevents duplicate alerts for the same finding on the same host.
    """
    try:
        from app.alerts.models import Alert
        from app.alerts.services import create_alert
    except ImportError:
        return

    for finding in findings:
        if finding.severity in ("critical", "high"):
            alert_title = f"[Vulnerability Scanner] {finding.title} on {finding.host}"
            existing = Alert.query.filter(
                Alert.title == alert_title,
                Alert.affected_host == finding.host,
                Alert.status.in_(["new", "acknowledged", "investigating"]),
            ).first()

            if not existing:
                try:
                    create_alert({
                        "title": alert_title,
                        "description": f"Automated vulnerability scan ({scan.scan_id}) detected {finding.severity.upper()} vulnerability on {finding.host}:{finding.port}. CVE: {finding.cve or 'N/A'}. {finding.description}",
                        "severity": finding.severity,
                        "category": "Vulnerability",
                        "source": "vulnerability_scanner",
                        "affected_host": finding.host,
                        "affected_asset": finding.host,
                        "metadata": {
                            "cve": finding.cve,
                            "cwe": finding.cwe,
                            "port": finding.port,
                            "service": finding.service,
                            "tool": finding.tool,
                            "scan_id": scan.scan_id,
                            "finding_id": finding.finding_id,
                        },
                    })
                except Exception:
                    pass


# ============================================================
# MULTI-TOOL SCAN EXECUTION PIPELINE (PHASE 16)
# ============================================================

def execute_scan(scan_id):
    """
    Executes the multi-tool vulnerability scanning pipeline:
    1. Scope / Authorization validation
    2. Target normalization & classification
    3. Safe DNS resolution
    4. Threat Intelligence correlation
    5. Nmap port & service discovery
    6. Web scanning (WhatWeb, Nikto, Nuclei, testssl) where applicable
    7. Finding normalization & deduplication
    8. Risk calculation & database persistence
    9. Alert Center integration
    """
    scan = Scan.query.filter_by(scan_id=scan_id).first()
    if not scan:
        return False, f"Scan '{scan_id}' not found."

    scan.status = "running"
    scan.started_at = datetime.utcnow()
    scan.error_message = None
    db.session.commit()

    targets = scan.targets
    if not targets:
        scan.status = "failed"
        scan.error_message = "No targets specified for scan."
        db.session.commit()
        return False, scan.error_message

    profile = (scan.profile or scan.scan_type or "STANDARD").upper()
    tools_used = set()
    raw_outputs = []
    dns_map = {}
    web_tech_list = []
    tls_results = {}
    collected_findings = []

    try:
        for tgt in targets:
            # 1. Normalize and validate target
            is_valid, target_info, err_msg = normalize_and_validate_target(tgt)
            if not is_valid:
                scan.status = "failed"
                scan.error_message = f"Target authorization failed for '{tgt}': {err_msg}"
                db.session.commit()
                return False, scan.error_message

            host = target_info.get("host") or tgt
            t_type = target_info.get("target_type") or "host"

            # 2. DNS Resolution
            if t_type in ("domain", "hostname", "url"):
                dns_res = resolve_target_dns(host)
                dns_map[host] = dns_res

            # 3. Threat Intelligence Correlation
            ti_indicators = [host]
            if host in dns_map and dns_map[host].get("ipv4"):
                ti_indicators.extend(dns_map[host]["ipv4"])
            ti_matches = correlate_threat_intel(ti_indicators)

            # 4. Nmap Execution
            success, xml_out, nmap_err = execute_nmap(
                host,
                scan_type=scan.scan_type,
                profile=profile,
                options=scan.options,
            )
            raw_outputs.append(f"=== Nmap: {host} ===\n{xml_out or nmap_err}")

            if success:
                tools_used.add("nmap")
                ports = parse_nmap_xml(xml_out, default_host=host)

                # Generate heuristic findings from Nmap
                for item in ports:
                    # Enrich with threat intel if matched
                    item_host = item.get("host") or host
                    if item_host in ti_matches:
                        item["threat_intel"] = ti_matches[item_host]

                # Run baseline evaluation
                heur_findings = evaluate_findings_from_ports(scan, ports, host)
                # Collected findings already created in DB by evaluate_findings_from_ports
            else:
                raw_outputs.append(f"Nmap warning: {nmap_err}")

            # 5. Web Assessment if applicable
            has_web = (t_type == "url") or any(p.get("port") in (80, 443, 8080, 8443, 3000, 5000, 8000) for p in (parse_nmap_xml(xml_out, default_host=host) if success else []))

            if has_web and profile in ("WEB", "STANDARD", "DEEP", "WEB APPLICATION SCAN", "FULL SCAN"):
                target_url = target_info.get("normalized") if t_type == "url" else f"http://{host}"

                # A. WhatWeb
                whatweb_results = run_whatweb_scan(target_url, timeout=40)
                if whatweb_results:
                    tools_used.add("whatweb")
                    web_tech_list.extend(whatweb_results)
                    raw_outputs.append(f"=== WhatWeb: {target_url} ===\nDetected {len(whatweb_results)} technologies.")

                # B. Nikto
                nikto_findings = run_nikto_scan(target_url, timeout=45)
                if nikto_findings:
                    tools_used.add("nikto")
                    raw_outputs.append(f"=== Nikto: {target_url} ===\nDiscovered {len(nikto_findings)} items.")
                    for nf in nikto_findings:
                        if host in ti_matches:
                            nf["threat_intel"] = ti_matches[host]
                        collected_findings.append(nf)

                # C. Nuclei
                nuclei_findings = run_nuclei_scan(target_url, timeout=45)
                if nuclei_findings:
                    tools_used.add("nuclei")
                    raw_outputs.append(f"=== Nuclei: {target_url} ===\nDiscovered {len(nuclei_findings)} template findings.")
                    for nuf in nuclei_findings:
                        if host in ti_matches:
                            nuf["threat_intel"] = ti_matches[host]
                        collected_findings.append(nuf)

                # D. testssl.sh (if HTTPS)
                if target_url.startswith("https://") or any(p.get("port") in (443, 8443) for p in (parse_nmap_xml(xml_out, default_host=host) if success else [])):
                    ssl_findings, ssl_summary = run_testssl_scan(host, port=443, timeout=45)
                    if ssl_findings:
                        tools_used.add("testssl")
                        tls_results[host] = ssl_summary
                        raw_outputs.append(f"=== testssl: {host} ===\nDiscovered {len(ssl_findings)} TLS findings.")
                        collected_findings.extend(ssl_findings)

            # Update ScanTarget record if exists
            tgt_rec = ScanTarget.query.filter(
                or_(
                    ScanTarget.name == host,
                    ScanTarget.target_value == host,
                )
            ).first()
            if tgt_rec:
                tgt_rec.last_scanned = datetime.utcnow()
                tgt_rec.risk_score = scan.risk_score
                if host in dns_map:
                    tgt_rec.dns_records = dns_map[host]

        # 6. Deduplicate and commit extra web/tool findings
        if collected_findings:
            deduped_web = deduplicate_and_merge_findings(collected_findings)
            extra_db_findings = []
            for wf in deduped_web:
                db_f = VulnerabilityFinding(
                    finding_id=generate_vuln_id(),
                    scan_id=scan.id,
                    cve=wf.get("cve") or "",
                    cwe=wf.get("cwe") or "",
                    title=wf["title"],
                    severity=wf.get("severity", "medium"),
                    cvss_score=wf.get("cvss_score", 5.0),
                    cvss_vector=wf.get("cvss_vector", ""),
                    description=wf["description"],
                    remediation=wf.get("remediation", "Review and harden configuration."),
                    host=wf.get("host", "target"),
                    port=wf.get("port"),
                    protocol=wf.get("protocol", "tcp"),
                    service=wf.get("service", "http"),
                    product=wf.get("product", ""),
                    version=wf.get("version", ""),
                    evidence=wf.get("evidence", ""),
                    tool=wf.get("tool", "multi-tool"),
                    confidence=wf.get("confidence", "confirmed"),
                    fingerprint=wf.get("fingerprint"),
                    threat_intel_json=json.dumps(wf.get("threat_intel") or {}),
                    affected_assets_json=json.dumps([wf.get("host", "target")]),
                    references_json=json.dumps(wf.get("references") or []),
                    status="open",
                    published_date=datetime.utcnow().strftime("%Y-%m-%d"),
                    discovered_at=datetime.utcnow(),
                )
                db.session.add(db_f)
                extra_db_findings.append(db_f)

            db.session.commit()
            integrate_alert_center(scan, extra_db_findings)

        # 7. Finalize scan metadata and status
        now = datetime.utcnow()
        duration_sec = (now - scan.started_at).total_seconds()
        scan.duration_min = max(1, int(round(duration_sec / 60.0)))
        scan.completed_at = now
        scan.status = "completed"
        scan.tools_used = sorted(list(tools_used))
        scan.dns_data = dns_map
        scan.web_technologies = web_tech_list
        scan.tls_summary = tls_results
        scan.raw_output = "\n---\n".join(raw_outputs)

        # Recalculate totals
        all_scan_findings = scan.findings.all()
        scan.total_findings = len(all_scan_findings)
        scan.critical_count = sum(1 for f in all_scan_findings if f.severity == "critical")
        scan.high_count = sum(1 for f in all_scan_findings if f.severity == "high")
        scan.medium_count = sum(1 for f in all_scan_findings if f.severity == "medium")
        scan.low_count = sum(1 for f in all_scan_findings if f.severity == "low")
        scan.risk_score = min(99, int(scan.critical_count * 25 + scan.high_count * 15 + scan.medium_count * 6 + scan.low_count * 2))
        scan.service_observations_count = len(scan.service_observations or [])

        db.session.commit()
        return True, "Scan completed successfully."

    except Exception as e:
        scan.status = "failed"
        scan.error_message = f"Unexpected scanner failure: {str(e)}"
        db.session.commit()
        return False, scan.error_message


def launch_scan_async(app, scan_id):
    """Launches scan execution in a background worker thread."""
    def worker():
        with app.app_context():
            execute_scan(scan_id)

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    return t


def create_scan(data, user_name="Analyst", run_immediately=True, app=None):
    """
    Creates a new Scan record and optionally triggers multi-tool execution.
    """
    name = str(data.get("name", "")).strip()
    if not name:
        name = f"Scan — {datetime.utcnow().strftime('%b %d %H:%M')}"

    scan_type = str(data.get("type") or data.get("scan_type") or "Standard Scan").strip()
    profile = str(data.get("profile") or ("QUICK" if "quick" in scan_type.lower() else "WEB" if "web" in scan_type.lower() else "DEEP" if "full" in scan_type.lower() or "deep" in scan_type.lower() else "STANDARD")).upper()

    targets = data.get("targets") or []
    if isinstance(targets, str):
        targets = [t.strip() for t in targets.split(",") if t.strip()]
    if not isinstance(targets, list) or len(targets) == 0:
        raise ValueError("At least one target is required.")

    # Validate each target before creation
    validated_targets = []
    for t in targets:
        is_val, t_info, msg = normalize_and_validate_target(t)
        if not is_val:
            raise ValueError(f"Invalid target '{t}': {msg}")
        validated_targets.append(t_info.get("normalized", t))

    options = data.get("options") or {}
    schedule_mode = str(data.get("scheduleMode") or data.get("schedule_mode") or "now").strip().lower()

    scan = Scan(
        scan_id=generate_scan_id(),
        name=name,
        scan_type=scan_type,
        profile=profile,
        status="running" if (schedule_mode == "now" and run_immediately) else "queued",
        started_at=datetime.utcnow(),
        initiated_by=user_name,
        targets_json=json.dumps(validated_targets),
        options_json=json.dumps(options if isinstance(options, dict) else {}),
        tools_used_json=json.dumps(["nmap"]),
        dns_data_json="{}",
        web_technologies_json="[]",
        tls_summary_json="{}",
        risk_score=0,
        total_findings=0,
    )

    db.session.add(scan)
    db.session.commit()

    if schedule_mode == "now" and run_immediately:
        if app:
            launch_scan_async(app, scan.scan_id)
        else:
            execute_scan(scan.scan_id)

    return scan


# ============================================================
# SCAN & VULNERABILITY QUERIES
# ============================================================

def get_scans(status=None, scan_type=None, search=None, page=1, per_page=10):
    """Returns paginated, filtered scans list."""
    query = Scan.query

    if status and str(status).strip():
        query = query.filter(Scan.status == str(status).strip().lower())

    if scan_type and str(scan_type).strip():
        query = query.filter(Scan.scan_type == str(scan_type).strip())

    if search and str(search).strip():
        term = f"%{str(search).strip()}%"
        query = query.filter(
            or_(
                Scan.name.ilike(term),
                Scan.scan_id.ilike(term),
                Scan.initiated_by.ilike(term),
                Scan.targets_json.ilike(term),
            )
        )

    query = query.order_by(desc(Scan.started_at))
    total = query.count()
    items = query.offset((page - 1) * per_page).limit(per_page).all()
    pages = (total + per_page - 1) // per_page if per_page > 0 else 1

    return {
        "items": [s.to_dict() for s in items],
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": pages,
    }


def get_scan_by_id(scan_id):
    """Fetches a single scan with its findings list."""
    scan = Scan.query.filter_by(scan_id=str(scan_id)).first()
    if not scan and str(scan_id).isdigit():
        scan = Scan.query.get(int(scan_id))
    if not scan:
        return None

    data = scan.to_dict()
    data["findings"] = [f.to_dict() for f in scan.findings.order_by(desc(VulnerabilityFinding.cvss_score)).all()]
    return data


def delete_scan(scan_id):
    """Deletes a scan and its associated findings."""
    scan = Scan.query.filter_by(scan_id=str(scan_id)).first()
    if not scan and str(scan_id).isdigit():
        scan = Scan.query.get(int(scan_id))
    if not scan:
        return False

    db.session.delete(scan)
    db.session.commit()
    return True


def get_vulnerabilities(severity=None, status=None, search=None, page=1, per_page=20):
    """Returns paginated and filtered vulnerability findings."""
    query = VulnerabilityFinding.query

    if severity:
        query = query.filter_by(severity=severity.lower())
    if status:
        query = query.filter_by(status=status.lower())
    if search:
        term = f"%{search}%"
        query = query.filter(
            or_(
                VulnerabilityFinding.title.ilike(term),
                VulnerabilityFinding.cve.ilike(term),
                VulnerabilityFinding.description.ilike(term),
                VulnerabilityFinding.host.ilike(term),
                VulnerabilityFinding.tool.ilike(term),
            )
        )

    pagination = query.order_by(desc(VulnerabilityFinding.discovered_at)).paginate(
        page=page,
        per_page=per_page,
        error_out=False,
    )
    return {
        "items": [item.to_dict() for item in pagination.items],
        "total": pagination.total,
        "page": pagination.page,
        "per_page": pagination.per_page,
        "pages": pagination.pages,
    }


def get_vulnerability_by_id(finding_id):
    """Fetches single vulnerability finding by ID."""
    finding = VulnerabilityFinding.query.filter_by(finding_id=str(finding_id)).first()
    if not finding and str(finding_id).isdigit():
        finding = VulnerabilityFinding.query.get(int(finding_id))
    return finding.to_dict() if finding else None


def update_vulnerability_status(finding_id, new_status):
    """Updates the lifecycle status of a vulnerability finding."""
    valid_statuses = ("open", "in_progress", "patched", "accepted_risk")
    clean_status = str(new_status).strip().lower().replace(" ", "_")
    if clean_status not in valid_statuses:
        raise ValueError(f"Invalid vulnerability status: '{new_status}'. Allowed: {valid_statuses}")

    finding = VulnerabilityFinding.query.filter_by(finding_id=str(finding_id)).first()
    if not finding and str(finding_id).isdigit():
        finding = VulnerabilityFinding.query.get(int(finding_id))
    if not finding:
        return None

    finding.status = clean_status
    db.session.commit()
    return finding.to_dict()


# ============================================================
# TARGETS MANAGEMENT (PHASE 2 & PHASE 3)
# ============================================================

def get_targets():
    """Returns all configured scan targets."""
    targets = ScanTarget.query.order_by(ScanTarget.name).all()
    return [t.to_dict() for t in targets]


def create_target(data, owner="Analyst"):
    """
    Creates a new ScanTarget with normalized target type and optional DNS pre-resolution.
    """
    name = str(data.get("name", "")).strip()
    if not name:
        raise ValueError("Target name is required.")

    target_val = str(data.get("target_value") or data.get("targetValue") or data.get("target_input") or data.get("targetInput") or name).strip()
    is_valid, t_info, msg = normalize_and_validate_target(target_val)
    if not is_valid:
        raise ValueError(f"Invalid target address/subnet: {msg}")

    # Check for duplicates
    existing = ScanTarget.query.filter(
        or_(
            ScanTarget.name.ilike(name),
            ScanTarget.target_value.ilike(t_info.get("normalized", target_val)),
        )
    ).first()
    if existing:
        raise ValueError(f"Target '{name}' or value '{target_val}' is already configured.")

    target_type = str(data.get("target_type") or data.get("type") or t_info.get("target_type", "Host")).strip().title()
    owner_name = str(data.get("owner", owner)).strip()

    # Pre-resolve DNS for hostnames/domains
    dns_records = {}
    host = t_info.get("host")
    if host and t_info.get("target_type") in ("domain", "hostname", "url"):
        dns_records = resolve_target_dns(host)

    target = ScanTarget(
        target_id=generate_target_id(),
        name=name,
        target_value=t_info.get("normalized", target_val),
        type=target_type,
        target_type=t_info.get("target_type", target_type),
        normalized_value=t_info.get("normalized", target_val),
        asset_count=int(data.get("asset_count", 1)),
        owner=owner_name,
        risk_score=0,
        is_authorized=bool(data.get("is_authorized", True)),
        dns_records_json=json.dumps(dns_records),
        parsed_url_json=json.dumps(t_info if t_info.get("target_type") == "url" else {}),
    )
    db.session.add(target)
    db.session.commit()
    return target


def delete_target(target_id):
    """Deletes a configured scan target."""
    target = ScanTarget.query.filter_by(target_id=str(target_id)).first()
    if not target and str(target_id).isdigit():
        target = ScanTarget.query.get(int(target_id))
    if not target:
        return False
    db.session.delete(target)
    db.session.commit()
    return True


def get_scan_findings(scan_id, severity=None, tool=None, search=None, page=1, per_page=50):
    """Returns paginated and filtered findings for a specific scan."""
    scan = Scan.query.filter_by(scan_id=str(scan_id)).first()
    if not scan and str(scan_id).isdigit():
        scan = Scan.query.get(int(scan_id))
    if not scan:
        return None

    query = VulnerabilityFinding.query.filter_by(scan_id=scan.id)
    if severity:
        query = query.filter_by(severity=severity.lower())
    if tool:
        query = query.filter_by(tool=tool.lower())
    if search:
        term = f"%{search}%"
        query = query.filter(
            or_(
                VulnerabilityFinding.title.ilike(term),
                VulnerabilityFinding.cve.ilike(term),
                VulnerabilityFinding.description.ilike(term),
                VulnerabilityFinding.host.ilike(term),
            )
        )
    pagination = query.order_by(desc(VulnerabilityFinding.cvss_score)).paginate(
        page=page,
        per_page=per_page,
        error_out=False,
    )
    return {
        "items": [item.to_dict() for item in pagination.items],
        "total": pagination.total,
        "page": pagination.page,
        "per_page": pagination.per_page,
        "pages": pagination.pages,
    }


# ============================================================
# SCANNER DASHBOARD STATS
# ============================================================

def get_scanner_dashboard_stats():
    """
    Computes all Scanner Dashboard KPIs, 14-day trend line data,
    severity distributions, recent scans, top affected hosts,
    and open critical/high vulnerabilities.
    """
    total_scans = Scan.query.count()
    active_scans = Scan.query.filter(Scan.status.in_(["running", "queued"])).count()
    critical_vulns = VulnerabilityFinding.query.filter(
        VulnerabilityFinding.severity == "critical",
        VulnerabilityFinding.status != "patched",
    ).count()

    all_scans = Scan.query.all()
    all_hosts = set()
    for s in all_scans:
        for t in s.targets:
            all_hosts.add(t)
    assets_scanned = len(all_hosts)

    scores = [s.risk_score for s in all_scans if s.risk_score > 0]
    avg_risk = int(round(sum(scores) / len(scores))) if scores else 0

    overdue = VulnerabilityFinding.query.filter(
        VulnerabilityFinding.severity.in_(["critical", "high"]),
        VulnerabilityFinding.status == "open",
    ).count()

    kpi = [
        {"label": "Total Scans", "value": total_scans, "accent": "accent-primary", "icon": "bi-search", "sub": f"{ScanTarget.query.count()} targets configured"},
        {"label": "Active Scans", "value": active_scans, "accent": "accent-info", "icon": "bi-hourglass-split", "sub": "running or queued"},
        {"label": "Critical Vulns", "value": critical_vulns, "accent": "accent-danger", "icon": "bi-exclamation-octagon", "sub": "unpatched"},
        {"label": "Assets Scanned", "value": assets_scanned, "accent": "accent-success", "icon": "bi-hdd-network", "sub": "unique hosts"},
        {"label": "Avg Risk Score", "value": avg_risk, "accent": "accent-warning", "icon": "bi-speedometer2", "sub": "0–99 scale"},
        {"label": "Overdue Remediation", "value": overdue, "accent": "accent-danger", "icon": "bi-clock-history", "sub": "critical/high, still open"},
    ]

    days = []
    now = datetime.utcnow()
    for i in range(13, -1, -1):
        d_str = (now - timedelta(days=i)).strftime("%Y-%m-%d")
        days.append(d_str)

    trend_counts = []
    for d in days:
        cnt = VulnerabilityFinding.query.filter(
            VulnerabilityFinding.published_date == d
        ).count()
        trend_counts.append(cnt)

    sev_order = ["critical", "high", "medium", "low"]
    sev_counts = {s: VulnerabilityFinding.query.filter_by(severity=s).count() for s in sev_order}

    recent_scans = Scan.query.order_by(desc(Scan.started_at)).limit(6).all()

    from sqlalchemy import func
    top_hosts_q = (
        db.session.query(VulnerabilityFinding.host, func.count(VulnerabilityFinding.id).label("cnt"))
        .group_by(VulnerabilityFinding.host)
        .order_by(desc("cnt"))
        .limit(6)
        .all()
    )
    max_host = top_hosts_q[0][1] if top_hosts_q else 1
    top_hosts = [{"host": h, "count": c, "percent": int(round(c / max_host * 100))} for h, c in top_hosts_q]

    critical_vulns_list = (
        VulnerabilityFinding.query.filter(
            VulnerabilityFinding.severity.in_(["critical", "high"]),
            VulnerabilityFinding.status != "patched",
        )
        .order_by(desc(VulnerabilityFinding.cvss_score))
        .limit(10)
        .all()
    )

    return {
        "kpi": kpi,
        "kpis": kpi,
        "trend": {
            "labels": [d[5:] for d in days],
            "counts": trend_counts,
        },
        "severity_distribution": sev_counts,
        "recent_scans": [s.to_dict() for s in recent_scans],
        "top_hosts": top_hosts,
        "critical_vulns": [v.to_dict() for v in critical_vulns_list],
    }


# ============================================================
# INITIAL SEED DATA
# ============================================================

def seed_initial_scanner_data():
    """
    Seeds initial baseline scans, vulnerabilities, and targets into PostgreSQL
    if tables are empty.
    """
    if ScanTarget.query.count() == 0:
        default_targets = [
            {"name": "Local Loopback", "val": "127.0.0.1", "type": "Host", "target_type": "ipv4", "count": 1, "score": 15, "owner": "SecOps"},
            {"name": "Production Web Tier", "val": "10.0.4.15", "type": "Cloud Account", "target_type": "ipv4", "count": 1, "score": 34, "owner": "R. Singh"},
            {"name": "Internal Finance Subnet", "val": "192.168.1.0/24", "type": "Subnet", "target_type": "cidr", "count": 24, "score": 74, "owner": "D. Okafor"},
            {"name": "Core Databases", "val": "10.0.2.10", "type": "Asset Group", "target_type": "ipv4", "count": 12, "score": 61, "owner": "R. Singh"},
            {"name": "DMZ Perimeter", "val": "192.168.1.1", "type": "Subnet", "target_type": "ipv4", "count": 8, "score": 47, "owner": "J. Chen"},
            {"name": "Kubernetes Cluster", "val": "k8s-node.local", "type": "Asset Group", "target_type": "hostname", "count": 4, "score": 29, "owner": "C. Martinez"},
            {"name": "Web Application App", "val": "http://127.0.0.1:5000", "type": "Web Application", "target_type": "url", "count": 1, "score": 40, "owner": "AppSec"},
            {"name": "IPv6 Lab Gateway", "val": "::1", "type": "Host", "target_type": "ipv6", "count": 1, "score": 10, "owner": "SecOps"},
        ]
        for item in default_targets:
            target = ScanTarget(
                target_id=generate_target_id(),
                name=item["name"],
                target_value=item["val"],
                type=item["type"],
                target_type=item["target_type"],
                normalized_value=item["val"],
                asset_count=item["count"],
                owner=item["owner"],
                risk_score=item["score"],
                is_authorized=True,
                dns_records_json="{}",
                parsed_url_json="{}",
            )
            db.session.add(target)
        db.session.commit()

    if Scan.query.count() == 0:
        s1 = Scan(
            scan_id="SCAN-8814",
            name="Production Web Sweep — Jul 22",
            scan_type="Quick Scan",
            profile="QUICK",
            status="completed",
            started_at=datetime.utcnow() - timedelta(days=2),
            completed_at=datetime.utcnow() - timedelta(days=2) + timedelta(minutes=12),
            duration_min=12,
            initiated_by="R. Singh",
            targets_json=json.dumps(["127.0.0.1", "10.0.4.15", "10.0.4.20"]),
            options_json=json.dumps({"service_detection": True}),
            tools_used_json=json.dumps(["nmap"]),
            dns_data_json="{}",
            web_technologies_json="[]",
            tls_summary_json="{}",
            risk_score=30,
            total_findings=4,
            critical_count=1,
            high_count=1,
            medium_count=1,
            low_count=1,
        )
        db.session.add(s1)
        db.session.commit()

        v1 = VulnerabilityFinding(
            finding_id=generate_vuln_id(),
            scan_id=s1.id,
            cve="CVE-2026-7618",
            cwe="CWE-22",
            title="Apache HTTP Server Path Traversal",
            severity="critical",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            description="Improper input validation allows path traversal on affected Apache HTTP Server installations.",
            remediation="Upgrade Apache HTTP Server to latest release.",
            host="127.0.0.1",
            port=443,
            protocol="tcp",
            service="https",
            product="Apache httpd",
            tool="nmap",
            confidence="confirmed",
            affected_assets_json=json.dumps(["127.0.0.1"]),
            references_json=json.dumps(["https://nvd.nist.gov/"]),
            status="open",
            published_date=datetime.utcnow().strftime("%Y-%m-%d"),
            discovered_at=datetime.utcnow(),
        )
        db.session.add(v1)
        db.session.commit()
