import os
from cryptography.fernet import Fernet


ENCRYPTION_KEY = os.environ.get(
    "ENCRYPTION_KEY", Fernet.generate_key().decode())
fernet = Fernet(ENCRYPTION_KEY.encode())


def encrypt_data(data: str) -> str:
    # Шифрует переданный текст и возвращает зашифрованную строку.
    return fernet.encrypt(data.encode()).decode()


def decrypt_data(encrypted_data: str) -> str:
    # Расшифровывает переданный зашифрованный текст и возвращает исходный секрет.
    return fernet.decrypt(encrypted_data.encode()).decode()
