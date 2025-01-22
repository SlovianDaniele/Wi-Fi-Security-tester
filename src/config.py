import os
from network_utils import get_local_path

class Config:
    """
    Клас для зберігання конфігурації
    """
    def __init__(self):
        self.settings = {
            "host": None,
            "username": "kali",
            "password": "kali",
            "handshake_folder": "handshake",
            "dict_folder": "dict",
            "hashcat_folder": "convert",
            "vm_name": "MAN"
        }

        # Створити папки для handshake, dict та hashcat, якщо вони не існують
        local_path = get_local_path()
        os.makedirs(os.path.join(local_path, self.settings["handshake_folder"]), exist_ok=True)
        os.makedirs(os.path.join(local_path, self.settings["dict_folder"]), exist_ok=True)
        os.makedirs(os.path.join(local_path, self.settings["hashcat_folder"]), exist_ok=True)

    # Оновити певний ключ в конфігурації
    def update(self, key, value):
        self.settings[key] = value

    # Отримати певний ключ з конфігурації
    def get(self, key):
        return self.settings[key]


config = Config()
