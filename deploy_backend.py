import paramiko
import os
import sys
from pathlib import Path

# Configuration
HOST = "168.222.194.141"
USER = "root"
PASS = "LKz2Qn22ytIXxeHn"
REMOTE_DIR = "/opt/turboproject/backend"
VENV_DIR = "/opt/turboproject/venv"
LOCAL_BACKEND_DIR = Path("backend").resolve()

def create_ssh_client():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print(f"Connecting to {HOST}...")
    client.connect(HOST, username=USER, password=PASS)
    return client

def run_command(client, command):
    print(f"Running: {command}")
    stdin, stdout, stderr = client.exec_command(command)
    exit_status = stdout.channel.recv_exit_status()
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    if exit_status != 0:
        print(f"Error executing command: {command}")
        print(f"Stderr: {err}")
        # Don't exit immediately, some commands might fail harmlessly (like user creation if exists)
    return out, err

def upload_files(sftp, local_path: Path, remote_path: str):
    print(f"Uploading {local_path} to {remote_path}...")
    
    # Ensure remote directory exists
    try:
        sftp.stat(remote_path)
    except FileNotFoundError:
        sftp.mkdir(remote_path)

    for item in local_path.iterdir():
        if item.name.startswith('.') or item.name == '__pycache__' or item.name == 'venv':
            continue
        
        remote_item_path = f"{remote_path}/{item.name}"
        
        if item.is_dir():
            try:
                sftp.stat(remote_item_path)
            except FileNotFoundError:
                sftp.mkdir(remote_item_path)
            upload_files(sftp, item, remote_item_path)
        else:
            sftp.put(str(item), remote_item_path)

def main():
    client = create_ssh_client()
    sftp = client.open_sftp()

    try:
        # 1. Install System Dependencies
        print("Installing system dependencies...")
        run_command(client, "apt-get update")
        run_command(client, "apt-get install -y python3-pip python3-venv postgresql postgresql-contrib libgdiplus")

        # 2. Configure PostgreSQL
        print("Configuring PostgreSQL...")
        run_command(client, "service postgresql start")
        # Create user 'RD' if not exists
        run_command(client, "sudo -u postgres psql -c \"DO $$ BEGIN IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'RD') THEN CREATE ROLE \\\"RD\\\" WITH LOGIN PASSWORD 'TurboProject'; END IF; END $$;\"")
        # Create DB 'poolresc' if not exists
        run_command(client, "sudo -u postgres psql -c \"SELECT 'CREATE DATABASE poolresc OWNER \\\"RD\\\"' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'poolresc')\\gexec\"")

        # 3. Prepare Directory
        print("Preparing application directories...")
        run_command(client, f"mkdir -p {REMOTE_DIR}")
        
        # 4. Upload Files
        print("Uploading backend files...")
        upload_files(sftp, LOCAL_BACKEND_DIR, REMOTE_DIR)

        # 5. Setup Python Environment
        print("Setting up Python virtual environment...")
        run_command(client, f"python3 -m venv {VENV_DIR}")
        run_command(client, f"{VENV_DIR}/bin/pip install --upgrade pip")
        run_command(client, f"{VENV_DIR}/bin/pip install -r {REMOTE_DIR}/requirements.txt")

        # 6. Create Systemd Service
        print("Creating systemd service...")
        service_content = f"""[Unit]
Description=TurboProject Backend
After=network.target postgresql.service

[Service]
User=root
WorkingDirectory={REMOTE_DIR}
ExecStart={VENV_DIR}/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
"""
        with sftp.file("/etc/systemd/system/turboproject-backend.service", "w") as f:
            f.write(service_content)

        # 7. Start Service
        print("Starting service...")
        run_command(client, "systemctl daemon-reload")
        run_command(client, "systemctl enable turboproject-backend")
        run_command(client, "systemctl restart turboproject-backend")
        
        print("Deployment completed successfully!")

    except Exception as e:
        print(f"Deployment failed: {e}")
    finally:
        sftp.close()
        client.close()

if __name__ == "__main__":
    main()
