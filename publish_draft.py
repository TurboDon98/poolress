import requests
import os

# GITHUB_TOKEN should be set in environment variables
token = os.environ.get("GITHUB_TOKEN", "")
headers = {
    "Authorization": f"token {token}",
    "Accept": "application/vnd.github.v3+json"
}

repo = "TurboDon98/poolress"
url = f"https://api.github.com/repos/{repo}/releases"

print(f"Fetching releases for {repo}...")
r = requests.get(url, headers=headers)
if r.status_code != 200:
    print(f"Error fetching releases: {r.status_code} {r.text}")
    exit(1)

releases = r.json()
target_release = None

for rel in releases:
    print(f"Found release: {rel['name']} (ID: {rel['id']}, Draft: {rel['draft']}, Tag: {rel['tag_name']})")
    if rel['tag_name'] == 'v0.1.4' or rel['name'] == '0.1.4':
        target_release = rel
        break

if target_release:
    print(f"Found target release 0.1.4 (ID: {target_release['id']}). Publishing...")
    update_url = f"https://api.github.com/repos/{repo}/releases/{target_release['id']}"
    data = {
        "draft": False,
        "prerelease": False,
        "make_latest": "true"
    }
    r = requests.patch(update_url, json=data, headers=headers)
    if r.status_code == 200:
        print("Successfully published release 0.1.4!")
    else:
        print(f"Failed to publish release: {r.status_code} {r.text}")
else:
    print("Release 0.1.4 not found.")
