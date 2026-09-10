# Security Architecture

Security is built into CyberDefense XDR by design, protecting both the application layer and the underlying operating environment. The application has undergone vulnerability assessments and includes several key defenses.

*For comprehensive external evaluation, reference the internal `docs/VAPT_SECURITY_REPORT.md` (if generated).*

## 1. Web Application Security Headers (OWASP)
The application globally enforces strict HTTP response headers via an `@app.after_request` middleware hook in `app/__init__.py`:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: SAMEORIGIN` (prevents Clickjacking)
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`
- **Content-Security-Policy (CSP)**: Strict rules restricting script, style, and object loading to trusted local/CDN sources, disabling inline arbitrary evaluation where possible.

## 2. Authentication & Session Management
- **CSRF Protection**: All POST/PUT/DELETE requests validate CSRF tokens via `Flask-WTF`.
- **Password Hashes**: Uses PBKDF2/bcrypt provided by Werkzeug Security.
- **Session Security**: Environment variables (`SESSION_COOKIE_SECURE`, `REMEMBER_COOKIE_SECURE`) enforce HTTPS-only cookies in production.
- **Brute-Force & Lockout**: Protections in `app/auth/routes.py` guard against rapid credential stuffing.

## 3. Role-Based Access Control (RBAC)
Access is managed via `app/user_management/decorators.py` and `app/user_management/permissions.py`.
Endpoints are strictly protected against Insecure Direct Object Reference (IDOR) and unauthorized horizontal/vertical privilege escalation. Restricted routes use decorators like `@role_required('admin')` or require specific feature flags.

## 4. Input Validation & Sanitization
Input processing across the platform uses multi-layer filtering to prevent injections:
- **Shell Injection Defense (Scanner)**: The `app/scanner/services.py` heavily validates target strings in `normalize_and_validate_target()`. It strictly filters out bash operational characters (`;`, `&`, `|`, `$`, `` ` ``) before handing over IPs/Domains to `subprocess.run()`.
- **Display Filter Validation (Packet Analysis)**: `app/packet_analysis/services.py` ensures that user-supplied Wireshark/TShark filters cannot inject arbitrary shell commands.
- **CSV Injection Defense (Audit Logs)**: Data exported from `app/audit_logs/routes.py` is sanitized. Cells beginning with formulas (`=`, `+`, `-`, `@`) are safely escaped or prefixed to prevent malicious macro execution in Excel/Calc.

## 5. AI Assistant Defenses
AI integrations are particularly vulnerable to prompt injection and data exfiltration. `app/ai_assistant/security.py` applies:
- **Secret Scrubbing**: Function `scrub_secrets()` automatically strips credentials, API keys, and sensitive tokens from user prompts using regex.
- **Data Boundary Wrapping**: `wrap_untrusted_data()` securely fences telemetry data to prevent "instruction smuggling", ensuring the LLM handles logs strictly as data rather than commands.
- **Length Bounds**: Input bounds limit token exhaustion (DoS) attempts.

## 6. Information Disclosure Prevention
Global error handlers in `app/__init__.py` ensure that stack traces or sensitive internal database errors are not leaked to end-users during production runtime. Unhandled exceptions return generic 500 error pages while logging the details securely to the server side.
