import paramiko

HOST = "168.222.194.141"
USER = "root"
PASS = "LKz2Qn22ytIXxeHn"

def get_logs():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print(f"Connecting to {HOST}...")
    client.connect(HOST, username=USER, password=PASS)

    print("Fetching logs...")
    # Check journalctl for the service
    stdin, stdout, stderr = client.exec_command("journalctl -u turboproject-backend -n 50 --no-pager")
    out = stdout.read().decode().strip()
    print(out)
    
    client.close()

if __name__ == "__main__":
    get_logs()
