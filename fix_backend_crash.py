import paramiko

HOST = "168.222.194.141"
USER = "root"
PASS = "LKz2Qn22ytIXxeHn"

def fix_crash():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print(f"Connecting to {HOST}...")
    client.connect(HOST, username=USER, password=PASS)

    print("Installing libicu-dev...")
    stdin, stdout, stderr = client.exec_command("apt-get update && apt-get install -y libicu-dev")
    print(stdout.read().decode())
    print(stderr.read().decode())

    print("Checking service file content...")
    stdin, stdout, stderr = client.exec_command("cat /etc/systemd/system/turboproject-backend.service")
    print(stdout.read().decode())

    print("Restarting service...")
    client.exec_command("systemctl restart turboproject-backend")
    
    # Wait a bit
    import time
    time.sleep(3)
    
    print("Checking service status...")
    stdin, stdout, stderr = client.exec_command("systemctl status turboproject-backend")
    print(stdout.read().decode())

    client.close()

if __name__ == "__main__":
    fix_crash()
