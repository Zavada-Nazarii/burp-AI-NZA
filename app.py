from flask import Flask, request, jsonify, render_template
import openai
import uuid
import os
import json

app = Flask(__name__, template_folder="templates", static_folder="static")
openai.api_key = open(".openai_key").read().strip() if os.path.exists(".openai_key") else None

analyzed_requests = {}

@app.route("/")
def index():
    return render_template("index.html", data=analyzed_requests)

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    session_id = str(uuid.uuid4())

    prompt = f"""
Ти експерт з безпеки веб-додатків. Проведи глибокий аналіз наведеного HTTP-запиту і:
- Визнач його призначення (наприклад, логін, реєстрація, пошук тощо)
- Визнач механізм автентифікації (BasicAuth, Token, Cookie, Session, JWT, тощо)
- Вкажи всі потенційні вразливості або ризики, що можуть бути у запиті. Врахуй наступні типи атак:
  - SQLi
  - XSS
  - SSRF
  - CSRF
  - RCE
  - IDOR
  - LFI/RFI
  - Graphql/API
  - JWT
  - CRLF
  - Web cache poisoning
  - Request smuggling
  - OWASP TOP 10
- Зазнач які параметри можуть бути вразливими до кожної атаки, де і як можна використати payload
- Вкажи загрози, пов'язані із заголовками запиту (якщо є). Особливо зверни увагу на:
  - `Host`
  - `User-Agent`
  - `X-Forwarded-For`
  - Інші заголовки, що можуть бути вразливими
- Напиши пояснення, чому це є вразливістю.
- Перевір, чи правильно обробляються параметри запиту, і чи не існує проблеми з безпекою.

Форматуй відповідь у вигляді JSON українською мовою:
{{
  "призначенняEndpoint": "...",
  "механізмАвтентифікації": "...",
  "потенційніВразливості": [
    {{
      "типАтаки": "SQLi",
      "параметр": "username",
      "payload": "' OR 1=1 --",
      "пояснення": "Можливість ін'єкції SQL"
    }},
    {{
      "типАтаки": "XSS",
      "параметр": "search_query",
      "payload": "<script>alert('XSS')</script>",
      "пояснення": "Можливість виконання коду через введення користувачем"
    }}
  ],
  "загрозиЗаголовків": [
    {{
      "заголовок": "Host",
      "ризик": "Можливість фальшування заголовка Host для обходу фільтрів"
    }},
    {{
      "заголовок": "X-Forwarded-For",
      "ризик": "Можливість фальшування IP-адреси через заголовок X-Forwarded-For"
    }}
  ],
  "коментар": "..."
}}

Метод: {data.get('method')}
Шлях: {data.get('path')}
Заголовки: {data.get('headers')}
Тіло: {data.get('body')}
"""

    try:
        completion = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "Ти асистент з кібербезпеки для тестування Web продукту на вразливості."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2
        )
        content = completion.choices[0].message["content"]
        parsed = json.loads(content)

        pretty_input = json.dumps(data, indent=2, ensure_ascii=False)
        pretty_output = json.dumps(parsed, indent=2, ensure_ascii=False)

        analyzed_requests[session_id] = {
            "id": session_id,
            "input": pretty_input,
            "output": parsed,
            "output_pretty": pretty_output,
            "attacks": None
        }

        return jsonify({"status": "ok", "sessionId": session_id}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/generate_attacks", methods=["POST"])
def generate_attacks():
    req = request.get_json()
    session_id = req.get("sessionId")
    if session_id not in analyzed_requests:
        return jsonify({"error": "Invalid session ID"}), 404

    data = analyzed_requests[session_id]["input"]
    parsed = json.loads(data)

    prompt = f"""
Згенеруй можливі точки для тестування на вразливості для HTTP-запиту. Для кожної точки вкажи:

- Тип атаки для потенційних векторів у цьому запиті (наприклад XSS, SQLi, SSRF, RCE, IDOR, HTTPP, Host header attack, CRLF та інші)
- Параметр або поле, яке підлягає тестуванню і підбадають під вказані вразлвості
- Приклад payload
- Пояснення щодо того, як цей параметр або поле може бути вразливим

Формат:
[
  {{
    "типАтаки": "SQLi",
    "поле": "username",
    "payload": "' OR 1=1 --",
    "пояснення": "Можливість ін'єкції SQL"
  }},
  {{
    "типАтаки": "XSS",
    "поле": "search_query",
    "payload": "<script>alert('XSS')</script>",
    "пояснення": "Можливість виконання коду через введення користувачем"
  }}
]

Ось HTTP-запит:
Метод: {parsed.get('method')}
Шлях: {parsed.get('path')}
Заголовки: {parsed.get('headers')}
Тіло: {parsed.get('body')}
"""

    try:
        completion = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "Ти асистент з кібербезпеки для тестування Web продукту на вразливості."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3
        )
        content = completion.choices[0].message["content"]
        attacks = json.loads(content)
        analyzed_requests[session_id]["attacks"] = attacks
        return jsonify({"status": "ok", "sessionId": session_id, "attacks": attacks})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(port=5000)

