import paramiko
import os

HOST = "168.222.194.141"
USER = "root"
PASS = "LKz2Qn22ytIXxeHn"

def fix_server():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        print(f"Connecting to {HOST}...")
        client.connect(HOST, username=USER, password=PASS)
        
        print("Installing libicu-dev (required for Aspose.Tasks/dotnet)...")
        # Ubuntu 24.04 might need specific version, but libicu-dev is usually a meta package
        stdin, stdout, stderr = client.exec_command("apt-get update && apt-get install -y libicu-dev")
        print(stdout.read().decode())
        err = stderr.read().decode()
        if err:
            print(f"Stderr: {err}")

        print("Restarting service...")
        client.exec_command("systemctl restart turboproject-backend")
        
        print("Checking status...")
        stdin, stdout, stderr = client.exec_command("systemctl status turboproject-backend")
        print(stdout.read().decode())
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    fix_server()
