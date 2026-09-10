# CyberDefense XDR — Troubleshooting Guide

This guide covers common operational, diagnostic, and deployment issues encountered in CyberDefense XDR, along with actionable resolutions.

---

## 1. Database & Migration Issues

### Error: `could not connect to server: Connection refused` or `OperationalError: connection to server at "localhost"`
- **Cause**: PostgreSQL is not running, listening on a different port, or network access is restricted (e.g., inside an isolated container sandbox).
- **Resolution**:
  - **Local**: Verify PostgreSQL service status:
    ```bash
    sudo systemctl status postgresql
    sudo systemctl start postgresql
    ```
  - **Docker**: Verify the `xdr-db` container is running and healthy:
    ```bash
    docker compose ps
    docker compose logs db
    ```
  - Check `DATABASE_URL` in `.env`. Ensure host is `localhost` for local runs and `db` for Docker Compose.

### Error: `UndefinedTable: relation "users" does not exist`
- **Cause**: Migrations have not been applied to the database.
- **Resolution**:
  ```bash
  # Local
  flask --app run.py db upgrade

  # Docker
  docker compose exec app flask --app run.py db upgrade
  ```

### Error: `Target database is not up to date` / Alembic conflict
- **Cause**: Database revision does not match the latest head in `migrations/versions/`.
- **Resolution**:
  ```bash
  flask --app run.py db current
  flask --app run.py db heads
  flask --app run.py db upgrade
  ```

---

## 2. Authentication & Account Lockout

### Issue: Account locked after 5 failed login attempts
- **Cause**: Built-in brute-force protection locks accounts for 15 minutes (`LOCKOUT_DURATION = 900s`).
- **Resolution**:
  - Wait 15 minutes for the lockout window to expire, or
  - Unlock via PostgreSQL CLI or Flask shell:
    ```bash
    # Via Flask shell
    python3 -c "
    from app import create_app
    from app.extensions import db
    from app.users.models import User
    app = create_app()
    with app.app_context():
        user = User.query.filter_by(username='YOUR_USERNAME').first()
        if user:
            user.failed_login_count = 0
            user.status = 'active'
            user.account_locked_until = None
            db.session.commit()
            print('Account unlocked successfully.')
    "
    ```

### Error: HTTP 403 `Account is inactive`
- **Cause**: User's `status` column is set to `"inactive"` or `is_active` is `False`.
- **Resolution**: An administrator must activate the account in `/user-management/` or via database update.

---

## 3. AI Assistant & Gemini Integration

### Issue: AI Assistant responses show heuristic/deterministic output instead of Gemini
- **Cause**: External API request failed, timed out, or returned an error (e.g., HTTP 503, invalid key). CyberDefense XDR automatically activates `LocalDeterministicProvider` as a zero-downtime fallback.
- **Diagnostics**:
  - Inspect provider status via API:
    ```bash
    curl -b cookies.txt http://localhost:5000/ai-assistant/api/status
    ```
  - Check application logs:
    ```bash
    tail -n 50 logs/xdr.log
    ```
- **Resolution**:
  - Verify `AI_API_KEY` is set correctly in `.env`.
  - Ensure `AI_API_BASE` is `https://generativelanguage.googleapis.com/v1beta/openai/`.
  - Ensure `AI_MODEL` is `gemini-3.6-flash`.
  - Confirm the system has outbound HTTPS internet access to Google's API endpoint.

### Issue: Gemini API returns HTTP 400 parameter errors
- **Cause**: Sending unsupported parameters such as `temperature` to certain Gemini endpoints.
- **Resolution**: The project's `OpenAICompatibleProvider` in [`app/ai_assistant/provider.py`](file:///home/kali/Projects/CyberDefense-XDR/app/ai_assistant/provider.py) automatically strips the `temperature` parameter when `AI_PROVIDER == "gemini"`. Ensure this logic remains intact.

---

## 4. Network IDS & Suricata

### Issue: Suricata fails to start with permission error (`AF_PACKET`)
- **Cause**: Non-root users cannot bind raw network sockets.
- **Resolution**:
  - CyberDefense XDR uses a privilege-safe pipeline: `dumpcap` (which has `cap_net_raw+eip`) captures packets and writes to a FIFO pipe at `instance/ids/suricata_pipe`, and Suricata reads from that pipe via `-r`.
  - Ensure `dumpcap` has capabilities configured:
    ```bash
    sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/dumpcap
    ```
  - Ensure the user running the application is in the `wireshark` group:
    ```bash
    sudo usermod -aG wireshark $USER
    ```

### Issue: Flood of "SURICATA TCPv4 invalid checksum" events (SID 2200074)
- **Cause**: NIC hardware checksum offloading causes packets captured by the OS to have invalid checksums before hardware computation.
- **Resolution**:
  - This is expected network behavior. CyberDefense XDR automatically classifies SID 2200074 as `diagnostic` noise in [`app/ids/services.py`](file:///home/kali/Projects/CyberDefense-XDR/app/ids/services.py).
  - Diagnostic events are logged to SIEM for full visibility, but are suppressed from triggering false positive alerts or incident escalations.
  - Suricata is also started with `-k none` to ignore checksum verification on live captures.

---

## 5. Packet Analysis & TShark

### Error: `TShark binary not found`
- **Cause**: Wireshark CLI tools are not installed.
- **Resolution**:
  ```bash
  # Debian / Ubuntu / Kali
  sudo apt-get update && sudo apt-get install -y tshark
  ```

### Error: `Invalid PCAP file header` on upload
- **Cause**: The uploaded file is corrupted or not a valid capture format.
- **Verification**: CyberDefense XDR validates magic bytes for standard PCAP (`0xa1b2c3d4`), nanosecond PCAP (`0xa1b23c4d`), and PCAPNG (`0x0a0d0d0a`). Verify the file with:
  ```bash
  capinfos /path/to/upload.pcap
  ```

### Error: `Invalid Wireshark display filter syntax`
- **Cause**: Filter string failed character whitelist validation or dry-run evaluation.
- **Resolution**: Use valid Wireshark filter syntax (e.g., `ip.addr == 192.168.1.1`, `tcp.port == 443`, `http`). Shell metacharacters (`;&|$\` etc.) are strictly rejected for security.

---

## 6. Vulnerability Scanner

### Issue: Nmap OS detection fails (`-O requires root privileges`)
- **Cause**: TCP SYN fingerprinting and OS detection (`-O`) require raw packet socket access (`cap_net_raw`).
- **Resolution**:
  - Use `LIGHT` or `STANDARD` scan profiles, which rely on standard connect scans and service banner grabbing (`-sV`).
  - For full OS detection, run the application with appropriate Linux capabilities or use host execution.

### Error: `Command contains forbidden characters`
- **Cause**: Target string contains disallowed characters (`;`, `&`, `|`, `` ` ``, `$`, `>`, `<`, `!`).
- **Resolution**: Pass only clean IP addresses (e.g., `192.168.1.50`), CIDR notations (`192.168.1.0/24`), hostnames (`target.corp.local`), or HTTP/HTTPS URLs.

---

## 7. Docker & Container Deployment

### Issue: Container health check fails (`unhealthy`)
- **Cause**: Application taking longer than 40 seconds to start, or database migrations failed during entrypoint execution.
- **Diagnosis**:
  ```bash
  docker compose logs -f app
  ```
- **Resolution**:
  - Check if PostgreSQL is ready: `docker compose exec db pg_isready -U cyberadmin`
  - Verify environment variables in `.env` are loaded properly.

### Issue: Permission denied in `instance/` directories
- **Cause**: Docker container runs as non-root user `xdr` (UID 999), and mounted host directories are owned by root.
- **Resolution**:
  ```bash
  sudo chown -R 999:999 instance/ logs/
  ```

---

## 8. CSRF & Form Errors

### Error: HTTP 400 `The CSRF session token is missing` / `CSRF token missing or invalid`
- **Cause**: Submitting an HTML form without a CSRF token, or session cookie expired.
- **Resolution**:
  - Ensure forms include `{{ csrf_token() }}` in a hidden `<input name="csrf_token">` field.
  - For AJAX / `fetch` requests, pass the token in the `X-CSRFToken` request header:
    ```javascript
    headers: {
      "X-CSRFToken": document.querySelector('meta[name="csrf-token"]').getAttribute("content")
    }
    ```

