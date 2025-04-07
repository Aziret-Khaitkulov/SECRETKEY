import asyncio
from datetime import datetime, timedelta
from typing import Optional


class SecretEntry:
    # Класс для хранения информации о секрете в кэше.
    def __init__(self, encrypted_secret: str, passphrase: Optional[str], expiration: datetime):
        self.encrypted_secret = encrypted_secret
        self.passphrase = passphrase
        self.expiration = expiration


# Глобальный кэш для хранения зашифрованных секретов и их паролей.
secrets_cache = {}


def add_secret(secret_key: str, encrypted_secret: str, passphrase: Optional[str], ttl_seconds: int):
    # Добавляет секрет в кэш.
    # TTL для хранения секрета не может быть меньше 300 секунд (5 минут).
    # Гарантированное минимальное время жизни – 5 минут
    ttl = max(ttl_seconds, 300)
    expiration_time = datetime.now() + timedelta(seconds=ttl)
    secrets_cache[secret_key] = SecretEntry(
        encrypted_secret, passphrase, expiration_time)


def get_secret(secret_key: str) -> Optional[SecretEntry]:
    # Получает секрет из кэша, если он существует и не просрочен.
    # Если срок действия истёк, удаляет его из кэша.
    entry = secrets_cache.get(secret_key)
    if entry:
        if datetime.now() < entry.expiration:
            return entry
        else:
            # Если срок жизни истёк, удаляем секрет
            del secrets_cache[secret_key]
    return None  # Секрет не найден или истёк


def delete_secret(secret_key: str):
    # Удаляет секрет из кэша.
    if secret_key in secrets_cache:
        del secrets_cache[secret_key]


async def clear_expired_secrets():
    # Асинхронная функция, которая периодически (раз в 60 секунд)
    # проходит по кэшу и удаляет просроченные секреты.
    while True:
        for key in list(secrets_cache.keys()):
            if datetime.now() >= secrets_cache[key].expiration:
                delete_secret(key)
        await asyncio.sleep(60)  # Ждём 60 секунд перед следующей проверкой
