import os
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime


DATABASE_URL = (
    f"postgresql://{os.getenv('POSTGRES_USER', 'postgres')}:"
    f"{os.getenv('POSTGRES_PASSWORD', 'postgres')}@"
    f"{os.getenv('POSTGRES_HOST', 'localhost')}:"
    f"{os.getenv('POSTGRES_PORT', '5432')}/"
    f"{os.getenv('POSTGRES_DB', 'secrets_db')}"
)


engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


class Log(Base):
    # Модель для логирования событий в сервисе.
    __tablename__ = "logs"
    # уникальный идентификатор записи
    id = Column(Integer, primary_key=True, index=True)
    secret_key = Column(String, index=True)  # ключ секрета
    action = Column(String)  # действие ("create", "read", "delete")
    timestamp = Column(DateTime, default=datetime.utcnow)  # время действия
    ip_address = Column(String, nullable=True)  # IP-адрес пользователя
    details = Column(Text, nullable=True)  # дополнительные детали действия


def init_db():
    # Функция инициализации БД: создаёт таблицы (если они не существуют).
    # Вызывается при старте приложения.
    Base.metadata.create_all(bind=engine)
