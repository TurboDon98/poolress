import paramiko
import time

HOST = "168.222.194.141"
USER = "root"
PASS = "LKz2Qn22ytIXxeHn"

def fix_db():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print(f"Connecting to {HOST}...")
    client.connect(HOST, username=USER, password=PASS)

    commands = [
        # Try to create user, ignore if exists (exit code might be non-zero but we continue)
        "sudo -u postgres psql -c \"CREATE ROLE \\\"RD\\\" WITH LOGIN PASSWORD 'TurboProject';\"",
        
        # Try to create DB
        "sudo -u postgres psql -c \"CREATE DATABASE poolresc OWNER \\\"RD\\\";\"",
        
        # Restart service to ensure it picks up the DB
        "systemctl restart turboproject-backend"
    ]

    for cmd in commands:
        print(f"Running: {cmd}")
        stdin, stdout, stderr = client.exec_command(cmd)
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        print(f"Output: {out}")
        if err:
            print(f"Error (might be harmless if 'already exists'): {err}")

    print("DB Fix completed.")
    client.close()

if __name__ == "__main__":
    fix_db()
