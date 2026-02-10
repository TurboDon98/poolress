import requests
import os

# GITHUB_TOKEN should be set in environment variables
token = os.environ.get("GITHUB_TOKEN", "")
headers = {
    "Authorization": f"token {token}",
    "Accept": "application/vnd.github.v3+json"
}

repo = "TurboDon98/poolress"
url = f"https://api.github.com/repos/{repo}/releases/tags/v0.1.4"

print(f"Checking status of v0.1.4...")
r = requests.get(url, headers=headers)
if r.status_code == 200:
    data = r.json()
    print(f"Release: {data['name']}")
    print(f"Draft: {data['draft']}")
    print(f"Prerelease: {data['prerelease']}")
    print(f"URL: {data['html_url']}")
else:
    print(f"Error: {r.status_code}")
