import requests
print('External check status:', requests.get('http://168.222.194.141:8000/docs', timeout=10).status_code)
