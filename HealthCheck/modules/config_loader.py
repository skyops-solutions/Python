import yaml


class ConfigLoader:
    def __init__(self, path):
        self.path = path
        self.config = None

    def load(self):
        with open(self.path) as f:
            self.config = yaml.safe_load(f)
        return self.config