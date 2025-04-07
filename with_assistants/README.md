# ChatGPT Assistant Integration

Цей проєкт демонструє, як інтегрувати **ChatGPT Assistant** API у веб-застосунок (Flask), для автоматичного аналізу HTTP-запитів з точки зору кібербезпеки.

---

## 🚀 Швидкий старт

1. Встанови залежності:
    ```bash
    pip install openai flask
    ```

2. Створи файл `.openai_key` у корені проєкту, в якому вкажи свій OpenAI API ключ:
    ```
    sk-...
    ```

3. Вкажи свій `ASSISTANT_ID` у `app.py`:
    ```python
    ASSISTANT_ID = "asst_xxxxxxxxxxxxx"
    ```

---

## 🔧 Налаштування асистента (ChatGPT Assistants)

1. Перейди на: https://platform.openai.com/assistants  
2. Натисни **"Create assistant"**
3. Введи:
    - **Name**: WebSec Analyzer
    - **Model**: GPT-4
    - **Instructions**:  
      _"Ти асистент з кібербезпеки. Аналізуй HTTP-запити, виявляй вразливості, повертай JSON з ключами: 'призначенняEndpoint', 'механізмАвтентифікації', 'потенційніВразливості' (як список об'єктів з полями типАтаки, пояснення, параметр, payload), 'коментар'."_

4. Натисни **"Create"**
5. Скопіюй `assistant_id` з URL або з info-панелі

---

## ⚙️ Що можна змінювати:

- `instructions` асистента — щоб кастомізувати стиль, глибину, формат
- `model` — GPT-4, 3.5, etc.
- `prompt` у `app.py` — щоб адаптувати під специфічні завдання (наприклад, GraphQL, API, JSON Schema)
- формат відповіді — наприклад, для інтеграції з іншими системами (SIEM, Burp)

---

## 🧪 Перевірка

- Запускай сервер:
    ```bash
    python app.py
    ```
- Відкрий у браузері: http://localhost:5000
- Надішли HTTP-запит через UI
- Отримай аналіз і payload-и

---

## 📁 Структура

```
├── app.py
├── templates/
│   └── index.html
├── static/
│   └── style.css
├── .openai_key
└── README.md
```

---

✅ Працює з OpenAI Assistants API  
✅ Повністю кастомізується  
✅ Підтримує веб-інтерфейс, автоматичний аналіз і збереження сесій