import os

GITIGNORE_CONTENT = """
# Виртуальное окружение
.venv/
venv/
env/

# Python кэш и компилированные файлы
__pycache__/
*.pyc
*.pyo
*.pyd

# Системные файлы Mac
.DS_Store

# Базы данных и личные файлы (НЕ ЗАЛИВАТЬ!)
user_db.json
inbox.json

# Ключи шифрования (ОЧЕНЬ ВАЖНО СКРЫТЬ!)
keys/
*.pem

# Загруженные файлы
src/uploads/
uploads/

# Временные скрипты для фиксов (не нужны в репозитории)
fix_*.py
setup_*.py
create_*.py
final_fix.py
cleanup.py
force_update.py
"""

def create_gitignore():
    path = ".gitignore"
    with open(path, "w", encoding="utf-8") as f:
        f.write(GITIGNORE_CONTENT.strip())
    print(f"✅ Файл {path} создан! Теперь Git будет игнорировать секретные файлы.")

if __name__ == "__main__":
    create_gitignore()