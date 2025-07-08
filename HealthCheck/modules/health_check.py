import requests

class HealthCheck:
    def __init__(self, url):
        self.url = url

    def check(self):
        try:
            response = requests.get(self.url, timeout=5)
            return response.status_code == 200
        except Exception as e:
            print(f'Error checking {self.url}: {e}')
        