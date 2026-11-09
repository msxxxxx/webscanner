"""Создаёт таблицы в БД. Запуск: .venv/bin/python -m scripts.init_db"""
from app.database import Base, engine
import app.models  # noqa: F401 — важно, чтобы модели зарегистрировались в Base


def main():
    Base.metadata.create_all(bind=engine)
    print("✅ Tables created:")
    for table in Base.metadata.sorted_tables:
        print(f"   • {table.name}")


if __name__ == "__main__":
    main()