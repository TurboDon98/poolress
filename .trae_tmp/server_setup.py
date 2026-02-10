import paramiko
import time

HOST = "168.222.194.141"
USER = "root"
PASS = "LKz2Qn22ytIXxeHn"

def run(c, cmd):
    print(f"\n$ {cmd}")
    stdin, stdout, stderr = c.exec_command(cmd)
    out = stdout.read().decode(errors="ignore")
    err = stderr.read().decode(errors="ignore")
    print(out.strip())
    if err.strip():
        print("ERR:", err.strip())
    return out, err

def main():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print(f"Connecting to {HOST} ...")
    client.connect(HOST, username=USER, password=PASS, timeout=20)

    # Ensure PostgreSQL installed and running
    run(client, "which psql || true")
    run(client, "apt-get update -y")
    run(client, "DEBIAN_FRONTEND=noninteractive apt-get install -y postgresql postgresql-contrib")
    run(client, "systemctl enable --now postgresql")
    run(client, "systemctl status postgresql --no-pager || true")
    run(client, "sudo -u postgres psql -c 'SELECT version();'")

    # Create role and DB per user request (quoted identifiers for case-sensitive names)
    run(client, "sudo -u postgres psql -c \"CREATE ROLE \\\"TurboProject_user\\\" WITH LOGIN PASSWORD 'TurboProject2808)';\" || true")
    run(client, "sudo -u postgres psql -c \"CREATE DATABASE \\\"TurboProject\\\" OWNER \\\"TurboProject_user\\\";\" || true")
    run(client, "sudo -u postgres psql -d \"TurboProject\" -c \"ALTER SCHEMA public OWNER TO \\\"TurboProject_user\\\";\" || true")
    run(client, "sudo -u postgres psql -c \"SELECT rolname FROM pg_roles WHERE rolname='TurboProject_user';\"")
    run(client, "sudo -u postgres psql -c \"SELECT datname FROM pg_database WHERE datname='TurboProject';\"")

    # Update systemd service with ENV pointing to new DB
    service = """[Unit]
Description=TurboProject Backend
After=network.target postgresql.service

[Service]
User=root
WorkingDirectory=/opt/turboproject/backend
Environment=FORCE_POSTGRES=1
Environment=PGHOST=localhost
Environment=PGPORT=5432
Environment=PGDATABASE=TurboProject
Environment=PGUSER=TurboProject_user
Environment=PGPASSWORD=TurboProject2808)
Environment=DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
ExecStart=/opt/turboproject/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
Restart=always

[Install]
WantedBy=multi-user.target
"""
    sftp = client.open_sftp()
    with sftp.file("/etc/systemd/system/turboproject-backend.service", "w") as f:
        f.write(service)
    sftp.close()

    run(client, "systemctl daemon-reload")
    run(client, "systemctl restart turboproject-backend")
    time.sleep(3)
    run(client, "systemctl status turboproject-backend --no-pager")
    run(client, "journalctl -u turboproject-backend -n 40 --no-pager || true")

    # Ensure firewall allows 8000
    run(client, "ufw status || true")
    run(client, "ufw allow 8000/tcp || true")
    run(client, "ufw reload || true")

    # Verify locally on server
    run(client, "curl -I http://127.0.0.1:8000/docs || true")

    client.close()
    print("Done.")

if __name__ == "__main__":
    main()
