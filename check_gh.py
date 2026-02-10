import requests
import os

token = "YOUR_GITHUB_TOKEN"
headers = {"Authorization": f"token {token}"}

print(f"Checking token for user...")
r = requests.get("https://api.github.com/user", headers=headers)
if r.status_code == 200:
    print(f"Token is valid. User: {r.json()['login']}")
else:
    print(f"Token invalid. Status: {r.status_code}, Response: {r.text}")
    exit(1)

print(f"\nChecking releases for TurboDon98/poolress...")
r = requests.get("https://api.github.com/repos/TurboDon98/poolress/releases", headers=headers)
if r.status_code == 200:
    releases = r.json()
    print(f"Found {len(releases)} releases.")
    for rel in releases:
        print(f"- {rel['name']} (Tag: {rel['tag_name']}, Draft: {rel['draft']}, Prerelease: {rel['prerelease']})")
else:
    print(f"Failed to list releases. Status: {r.status_code}, Response: {r.text}")
