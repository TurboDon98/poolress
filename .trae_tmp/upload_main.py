import paramiko

HOST = "168.222.194.141"
USER = "root"
PASS = "LKz2Qn22ytIXxeHn"
LOCAL = r"c:\Users\r.davletov\Desktop\Codes\TurboProject 2.0\backend\app\main.py"
REMOTE = "/opt/turboproject/backend/app/main.py"

print(f"Connecting to {HOST} ...")
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(HOST, username=USER, password=PASS)

print("Uploading main.py ...")
sftp = client.open_sftp()
with open(LOCAL, "rb") as lf:
    data = lf.read()
with sftp.file(REMOTE, "w") as rf:
    rf.write(data.decode("utf-8"))
sftp.close()

print("Restarting service ...")
stdin, stdout, stderr = client.exec_command("systemctl restart turboproject-backend && sleep 2 && systemctl status turboproject-backend --no-pager")
print(stdout.read().decode())
print(stderr.read().decode())

client.close()
print("Done.")
