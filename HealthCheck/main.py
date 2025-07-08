from modules.config_loader import ConfigLoader
from modules.health_check import HealthCheck

def main():
    loader = ConfigLoader('config/config.yml')
    config = loader.load()

    for server in config['servers']:
        url = server.get('host')
        if url:
            checker = HealthCheck(url)
            result = checker.check()
            print(f"{server['host']} health check: {'OK' if result else 'FAIL'}")

if __name__ == "__main__":
    main()