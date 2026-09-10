# Configuration Guide

CyberDefense XDR uses environment variables for secure and scalable configuration. A `.env.example` file is provided in the repository root. Copy it to `.env` to configure your instance.

> [!IMPORTANT]
> Never commit your `.env` file to version control.

## Environment Variables

### Application Settings
| Variable | Default Value | Description |
|----------|---------------|-------------|
| `FLASK_APP` | `run.py` | The entry point for the Flask CLI. |
| `FLASK_ENV` | `production` | Set to `development` to enable debug features (Warning: Insecure in production). |
| `DEBUG` | `False` | Enables/disables Flask debugging output. |
| `APP_NAME` | `CyberDefense XDR` | The name of the application displayed in the UI. |
| `VERSION` | `0.1.0` | Current application version. |

### Database
| Variable | Default Value | Description |
|----------|---------------|-------------|
| `DATABASE_URL` | `postgresql://...` | Connection string for the PostgreSQL database (e.g., `postgresql://user:pass@localhost:5432/db_name`). |

### Security
| Variable | Default Value | Description |
|----------|---------------|-------------|
| `SECRET_KEY` | *None* | Used for signing session cookies and CSRF tokens. Generate a secure random string (e.g., `python -c "import secrets; print(secrets.token_hex(32))"`). |
| `SESSION_COOKIE_SECURE` | `False` | Set to `True` in production if serving over HTTPS to prevent cookies from being sent in plaintext. |
| `REMEMBER_COOKIE_SECURE`| `False` | Set to `True` for HTTPS environments. |
| `WTF_CSRF_ENABLED` | `True` | Enforces CSRF token validation on form submissions. |

### AI Assistant (Gemini)
| Variable | Default Value | Description |
|----------|---------------|-------------|
| `AI_PROVIDER` | `gemini` | The AI provider to use. Defaults to `gemini` (can be set to `mock` for testing). |
| `AI_API_KEY` | *None* | API key for the Gemini service. |
| `AI_API_BASE` | Google API URL | Base URL for the AI API endpoint. |
| `AI_MODEL` | `gemini-3.6-flash` | The specific model identifier to use (e.g., `gemini-2.5-flash`). |
| `AI_TIMEOUT` | `60` | Request timeout in seconds. |
| `AI_MAX_TOKENS` | `1200` | Maximum token limit for generation responses. |

### Network IDS
*Note: Configures log rotation and ingestion for host-based IDS integration.*
| Variable | Default Value | Description |
|----------|---------------|-------------|
| `IDS_LOG_ROTATION_SIZE_MB` | `100` | Maximum size in MB before IDS logs are rotated. |
| `IDS_LOG_RETENTION_FILES` | `7` | Number of rotated log files to retain. |
| `IDS_LOG_ROTATION_INTERVAL_SECONDS` | `60` | Frequency of checking log size. |

### Packet Analysis
| Variable | Default Value | Description |
|----------|---------------|-------------|
| `MAX_PCAP_UPLOAD_MB` | `50` | Maximum size limit for PCAP file uploads in Megabytes. |
| `TSHARK_TIMEOUT_SECONDS` | `120` | Timeout for background TShark processing operations. |

### Mail (Optional)
| Variable | Default Value | Description |
|----------|---------------|-------------|
| `MAIL_SERVER` | `smtp.gmail.com` | SMTP server for sending out emails/notifications. |
| `MAIL_PORT` | `587` | Port for the SMTP server. |
| `MAIL_USE_TLS` | `True` | Enable TLS for SMTP connection. |
| `MAIL_USERNAME` | *None* | Username for mail authentication. |
| `MAIL_PASSWORD` | *None* | Password/App Password for mail authentication. |
| `MAIL_DEFAULT_SENDER`| *None* | Default "From" email address. |
