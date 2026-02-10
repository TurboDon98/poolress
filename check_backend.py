import requests

try:
    r = requests.get("http://168.222.194.141:8000/docs", timeout=5)
    print(f"Status Code: {r.status_code}")
    if r.status_code == 200:
        print("Backend is reachable!")
    else:
        print("Backend returned non-200 status.")
except Exception as e:
    print(f"Failed to connect: {e}")
