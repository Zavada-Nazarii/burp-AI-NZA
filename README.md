# 🔍 GPT API Analyzer for Burp Suite

> **AI-асистент для аналізу HTTP-запитів із Burp Suite через локальне GPT API.**

Цей проєкт дозволяє автоматично аналізувати HTTP-запити з Burp Suite, генерувати можливі вразливості та payload'и за допомогою GPT, та інтерактивно переглядати результати в зручному веб-інтерфейсі.

---

## 🎯 Ціль проекту

- Автоматизувати аналіз HTTP-запитів під час пентесту.
- Отримувати миттєві припущення про вразливості на основі AI.
- Генерувати payload'и до знайдених параметрів.
- Зберігати результати у зручному форматі (HTML/JSON).

---

## 🧩 Архітектура

```
[Burp Suite] --> [Burp Extension (Python/Jython)] --> [Flask API Backend (localhost:5000)] --> [HTML Web UI]
```

---

## 🚀 Встановлення

### 1. Встановити Flask Backend

```bash
git clone https://github.com/Zavada-Nazarii/burp-AI-NZA.git
cd burp-AI-NZA
pip install -r requirements.txt
python app.py
```

> ⚠️ API запускається локально на `http://localhost:5000`

### 2. Інсталювати Burp Extension

1. Відкрий Burp Suite.
2. Перейди до **Extender → Extensions**.
3. Додай нове розширення:
   - **Extension type**: Python
   - **Extension file**: `burp-AI-NZA/GPTAnalyzer.py`

---

## 🛠️ Як користуватись

1. Запусти Flask backend: `python app.py`
2. У Burp Suite клікни ПКМ на будь-який HTTP-запит **Extensions** → **GPT API Analyzer** → **Analyze with GPT**.
3. Результати з'являться у веб-інтерфейсі (`http://localhost:5000`).
4. Натисни **"Згенерувати пейлоуди"**, щоб отримати можливі варіанти атак.
5. Натисни **"Зберегти повністю"** — отримаєш повний звіт у `.html`.

---

## 🔑 API ключ

- У даному проєкті GPT інтеграція працює через використати зовнішнього GPT API:
  - додай `.openai_key` файл у /burp-AI-NZA з ключем:
    ```env
    your-key-here
    ```
---

## 📁 Структура проєкту

```
burp-AI-NZA/
    ├── app.py             # Flask API сервер
    ├── templates/         # HTML-шаблон
    ├── GPTAnalyzer.py     # Розширення для Burp Suite
    ├── README.md          # README
    └── static/            # Стилі

```

---

## 🧠 Приклад JSON-запиту з Burp

```json
{
  "method": "POST",
  "path": "/api/user",
  "headers": ["Host: example.com", "Content-Type: application/json"],
  "body": "{\"userId\": \"123\"}"
}
```

---

## 👨‍💻 Інтеграція із assistants

[ChatGPT Assistant Integration](https://github.com/Zavada-Nazarii/burp-AI-NZA/tree/master/with_assistants)

---

## ✅ TODO / Ідеї

- Додати підтримку OpenAI GPT-4.
- Підключити базу знань OWASP для перевірки класів вразливостей.
- Додати збереження результатів до SQLite або MongoDB.

---

© GPT API Analyzer — для етичного використання під час тестування безпеки
