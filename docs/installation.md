# Installation Guide

## Prerequisites
- **Operating System**: Linux (Ubuntu/Debian or Kali Linux recommended)
- **Python**: Version 3.13+
- **Database**: PostgreSQL 15+
- **System Packages** (for security modules):
  ```bash
  sudo apt update
  sudo apt install tshark nmap nikto whatweb suricata testssl.sh
  ```
  *(Note: Nuclei must be installed separately via Go or downloading the binary).*

## Step 1: Clone the Repository
```bash
git clone https://github.com/sam29sahil/CyberDefense-XDR.git
cd CyberDefense-XDR
```

## Step 2: Virtual Environment Setup
```bash
python3.13 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Step 3: PostgreSQL Database Creation
Log into the PostgreSQL prompt:
```bash
sudo -u postgres psql
```
Create the database and user:
```sql
CREATE DATABASE cyberdefense_xdr;
CREATE USER cyberadmin WITH PASSWORD 'your_password_here';
GRANT ALL PRIVILEGES ON DATABASE cyberdefense_xdr TO cyberadmin;
ALTER DATABASE cyberdefense_xdr OWNER TO cyberadmin;
\q
```

## Step 4: Environment Configuration
Copy the sample environment file:
```bash
cp .env.example .env
```
Edit `.env` and fill in the required configurations, specifically the `DATABASE_URL` and `SECRET_KEY`. See [Configuration](configuration.md) for full details.

## Step 5: Database Migrations
Initialize the database schema using Flask-Migrate (Alembic):
```bash
flask --app run.py db upgrade
```
*(This will run all 23 migration files and set up the 31 database tables).*

## Step 6: Running the Application

### Development Server
Run the built-in Flask development server:
```bash
flask --app run.py run --host=0.0.0.0 --port=5000
```
> [!WARNING]
> Do not use the Flask development server in a production environment.

### Production Server (Gunicorn)
For production deployments, use Gunicorn:
```bash
gunicorn -w 4 -b 0.0.0.0:5000 "run:app"
```

## Optional Tools Installation
To fully utilize the XDR capabilities:
1. **Gemini AI**: Obtain an API key from Google AI Studio and configure `AI_API_KEY` in your `.env`.
2. **Suricata**: Ensure Suricata is generating `eve.json` logs and route them into the application's IDS module log ingestion path.
