import paramiko

HOST = "168.222.194.141"
USER = "root"
PASS = "LKz2Qn22ytIXxeHn"

QUERY = (
    "sudo -u postgres psql -d \"TurboProject\" "
    "-c \"SELECT id, email, username, full_name, department, created_at FROM users ORDER BY id DESC LIMIT 10;\""
)

print(f"Connecting to {HOST} ...")
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(HOST, username=USER, password=PASS)

print("Querying recent users ...")
stdin, stdout, stderr = client.exec_command(QUERY)
print(stdout.read().decode())
err = stderr.read().decode()
if err.strip():
    print("ERR:", err)

client.close()
print("Done.")
