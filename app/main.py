import uuid
import asyncio

from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from contextlib import asynccontextmanager

from app.encryption import encrypt_data, decrypt_data
from app.cache import add_secret, get_secret, delete_secret, clear_expired_secrets
from app.db import SessionLocal, init_db, Log


class CreateSecretRequest(BaseModel):
    secret: str  # Секрет, который нужно сохранить
    passphrase: str  # Пароль для шифрования секрета
    ttl: int = 300  # Время жизни секрета в секундах (по умолчанию 5 минут)


class CreateSecretResponse(BaseModel):
    secret_key: str  # Ключ секрета для доступа к нему


class GetSecretResponce(BaseModel):
    secret: str  # Запрашиваемый секрет


class DeleteSecretResponse(BaseModel):
    status: str  # Статус удаления секрета


# Функция логирования событий в БД.
def log_event(secret_key: str, action: str, ip_address: str, details: str = None):
    # Добавляет запись (лог) о событии в базу данных.
    db = SessionLocal()
    try:
        log_entry = Log(secret_key=secret_key, action=action,
                        ip_address=ip_address, details=details)
        db.add(log_entry)
        db.commit()
    except Exception as exc:
        print(f"Ошибка при логировании события: {exc}")
    finally:
        db.close()


# Событие при старте приложения
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Действия при старте приложения
    init_db()
    task = asyncio.create_task(clear_expired_secrets())
    try:
        yield  # Здесь приложение работает
    finally:
        # Действия при завершении приложения
        task.cancel()

app = FastAPI(title="Одноразовые секреты",
              description="Сервис для безопасного хранения и одноразового получения секретов",
              lifespan=lifespan)


# Эндпоинт для создания секрета
@app.post("/secrets", response_model=CreateSecretResponse,
          summary="Создание секрета",
          description="Создаёт новый секрет. Секрет шифруется и сохраняется в кэше с указанным временем жизни (TTL). "
          "Возвращает уникальный ключ для доступа к секрету.")
async def create_secret(request: Request, payload: CreateSecretRequest):
    # Создаёт секрет:
    #   - Генерируется уникальный идентификатор (secret_key).
    #   - Секрет шифруется и сохраняется в кэше с TTL не менее 5 минут.
    #   - Логируется событие создания секрета.
    # Генерируем уникальный идентификатор для секрета.
    secret_key = str(uuid.uuid4())
    encrypted = encrypt_data(payload.secret)  # Шифруем секрет.
    # Устанавливаем TTL (время жизни) секрета.
    ttl = max(payload.ttl, 300)
    add_secret(secret_key, encrypted, payload.passphrase, ttl)

    # Логируем событие создания, фиксируя IP-адрес клиента
    client_host = request.client.host
    log_event(secret_key, "create", client_host,
              details=f"TTL: {ttl}, Passphrase provided: {bool(payload.passphrase)}")

    # Возвращаем ключ секрета клиенту.
    return CreateSecretResponse(secret_key=secret_key)


# Эндпоинт для получения секрета
@app.get("/secrets/{secret_key}", response_model=GetSecretResponce, summary="Получение секрета",
         description="Получает секрет по уникальному ключу. Если секрет существует, он удаляется из кэша после первого запроса.")
async def get_secret_endpoint(secret_key: str, request: Request):
    # Возвращает секрет по уникальному ключу при первом запросе и затем удаляет его из кэша.
    # После успешного чтения секрета производится логирование.
    entry = get_secret(secret_key)
    if not entry:
        raise HTTPException(
            status_code=404, detail="Секрет не найден или истёк срок его действия.")
    try:
        # Расшифровываем сохранённое значение секрета.
        plain_text = decrypt_data(entry.encrypted_secret)
    except Exception:
        raise HTTPException(
            status_code=500, detail="Ошибка при расшифровке секрета.")

    delete_secret(secret_key)  # Удаляем секрет из кэша после его получения.
    client_host = request.client.host
    log_event(secret_key, "read", client_host)
    return GetSecretResponce(secret=plain_text)


# Эндпоинт для удаления секрета
@app.delete("/secrets/{secret_key}", response_model=DeleteSecretResponse, summary="Удаление секрета",
            description="Удаляет секрет по уникальному ключу. Если секрет защищён паролем, он должен быть передан для удаления.")
async def delete_secret_endpoint(secret_key: str, request: Request, passphrase: str = None):
    # Удаление секрета:
    #   - Если при создании секрета использовалась passphrase, то для удаления она должна быть передана и проверена.
    #   - При успешном удалении секрет становится недоступным для дальнейших запросов.
    #   - Событие удаления логируется в БД.
    entry = get_secret(secret_key)
    if not entry:
        raise HTTPException(
            status_code=404, detail="Секрет не найден или истёк срок его действия.")

    # Если секрет защищён passphrase, необходимо проверить его корректность.
    if entry.passphrase:
        if not passphrase or passphrase != entry.passphrase:
            raise HTTPException(
                status_code=403, detail="Неверный пароль для удаления секрета.")

    # Удаляем секрет из кэша.
    delete_secret(secret_key)
    client_host = request.client.host
    log_event(secret_key, "delete", client_host)

    return DeleteSecretResponse(status="Секрет успешно удалён.")


# Middleware для запрета клиентского кеширования.
@app.middleware("http")
async def add_cache_control_header(request: Request, call_next):
    # Добавление HTTP-заголовков, запрещающих кеширование на стороне клиента и прокси.
    responce = await call_next(request)
    responce.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    responce.headers["Pragma"] = "no-cache"
    responce.headers["Expires"] = "0"
    return responce
