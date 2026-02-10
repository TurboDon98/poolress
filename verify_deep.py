import paramiko
import os

HOST = "168.222.194.141"
USER = "root"
PASS = "LKz2Qn22ytIXxeHn"

def check_remote_details():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        print(f"Connecting to {HOST}...")
        client.connect(HOST, username=USER, password=PASS)
        
        print("\n--- Checking app/db.py content ---")
        stdin, stdout, stderr = client.exec_command("cat /opt/turboproject/backend/app/db.py")
        content = stdout.read().decode()
        if "TurboProject" in content:
            print("SUCCESS: Password 'TurboProject' found in db.py")
        else:
            print("FAILURE: Password 'TurboProject' NOT found in db.py")
            # print(content) # Print full content if needed for debug

        print("\n--- Checking Service Status ---")
        stdin, stdout, stderr = client.exec_command("systemctl status turboproject-backend")
        print(stdout.read().decode())
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    check_remote_details()
