import paramiko
import os

HOST = "168.222.194.141"
USER = "root"
PASS = "LKz2Qn22ytIXxeHn"

def force_invariant_mode():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        print(f"Connecting to {HOST}...")
        client.connect(HOST, username=USER, password=PASS)
        
        print("Modifying systemd service to use Invariant Globalization...")
        # Use sed to insert the Environment line into the [Service] section
        # This is a bit hacky but efficient. 
        # Or we can just rewrite the file. Rewriting is safer.
        
        service_content = """[Unit]
Description=TurboProject Backend
After=network.target postgresql.service

[Service]
User=root
WorkingDirectory=/opt/turboproject/backend
ExecStart=/opt/turboproject/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
Environment=DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1
Restart=always

[Install]
WantedBy=multi-user.target
"""
        sftp = client.open_sftp()
        with sftp.file("/etc/systemd/system/turboproject-backend.service", "w") as f:
            f.write(service_content)
        sftp.close()

        print("Reloading and restarting service...")
        client.exec_command("systemctl daemon-reload")
        client.exec_command("systemctl restart turboproject-backend")
        
        print("Checking status...")
        stdin, stdout, stderr = client.exec_command("systemctl status turboproject-backend")
        print(stdout.read().decode())
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    force_invariant_mode()
