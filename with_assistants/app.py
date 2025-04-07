from flask import Flask, request, jsonify, render_template
import openai
import uuid
import os
import json
import time
import traceback
import re

app = Flask(__name__, template_folder="templates", static_folder="static")
openai.api_key = open(".openai_key").read().strip() if os.path.exists(".openai_key") else None

ASSISTANT_ID = "asst_......"  # Заміни на свій

analyzed_requests = {}

@app.route("/")
def index():
    return render_template("index.html", data=analyzed_requests)

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    session_id = str(uuid.uuid4())

    user_prompt = f"""
Ти експерт з безпеки веб-додатків. Проведи глибокий аналіз наведеного HTTP-запиту і вкажи всі потенційні вразливості або ризики, що можуть бути у запиті. 
Врахуй наступні типи атак:
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

Поверни JSON українською мовою з такими ключами:
- "призначенняEndpoint"
- "механізмАвтентифікації"
- "потенційніВразливості" — список об'єктів:
  типАтаки, пояснення, параметр, payload
- "коментар"

Метод: {data.get('method')}
Шлях: {data.get('path')}
Заголовки: {data.get('headers')}
Тіло: {data.get('body')}
"""

    try:
        thread = openai.beta.threads.create()
        openai.beta.threads.messages.create(
            thread_id=thread.id,
            role="user",
            content=user_prompt
        )
        run = openai.beta.threads.runs.create(
            thread_id=thread.id,
            assistant_id=ASSISTANT_ID
        )

        while True:
            run_status = openai.beta.threads.runs.retrieve(
                thread_id=thread.id,
                run_id=run.id
            )
            if run_status.status == "completed":
                break
            elif run_status.status in ["failed", "cancelled"]:
                return jsonify({"error": "Асистент не зміг обробити запит"}), 500
            time.sleep(1)

        messages = openai.beta.threads.messages.list(thread_id=thread.id)
        answer = messages.data[0].content[0].text.value
        print("🔍 Відповідь від GPT:\n", answer)

        # Очистка markdown, лапок
        cleaned = answer.strip()
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(json)?", "", cleaned)
            cleaned = re.sub(r"```$", "", cleaned)
        cleaned = cleaned.replace("“", "\"").replace("”", "\"").replace("‘", "'").replace("’", "'")

        try:
            parsed = json.loads(cleaned)

            if isinstance(parsed.get("потенційніВразливості"), list):
                converted = []
                for item in parsed["потенційніВразливості"]:
                    if isinstance(item, dict):
                        converted.append({
                            "типАтаки": item.get("типАтаки") or item.get("назва") or "—",
                            "пояснення": item.get("пояснення") or item.get("опис") or "—",
                            "параметр": item.get("параметр", ""),
                            "payload": item.get("payload", "")
                        })
                    elif isinstance(item, str):
                        converted.append({
                            "типАтаки": "—",
                            "пояснення": item,
                            "параметр": "",
                            "payload": ""
                        })
                parsed["потенційніВразливості"] = converted

            parsed.setdefault("призначенняEndpoint", "—")
            parsed.setdefault("механізмАвтентифікації", "—")
            parsed.setdefault("потенційніВразливості", [])
            parsed.setdefault("коментар", "—")

        except json.JSONDecodeError as e:
            print("❌ JSON помилка:", str(e))
            parsed = {
                "призначенняEndpoint": "—",
                "механізмАвтентифікації": "—",
                "потенційніВразливості": [],
                "коментар": "⚠️ GPT не повернув валідний JSON",
                "output": answer
            }

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
        print("❌ Виникла помилка:\n", traceback.format_exc())
        return jsonify({"error": str(e)}), 500

@app.route("/generate_attacks", methods=["POST"])
def generate_attacks():
    req = request.get_json()
    session_id = req.get("sessionId")
    if session_id not in analyzed_requests:
        return jsonify({"error": "Invalid session ID"}), 404

    data = analyzed_requests[session_id]["input"]
    parsed = json.loads(data)

    user_prompt = f"""
Згенеруй можливі точки для тестування на вразливості для HTTP-запиту. Для кожної точки вкажи:

- Тип атаки для потенційних векторів у цьому запиті (наприклад XSS, SQLi, SSRF, RCE, IDOR, HTTPP, Host header attack, CRLF та інші)
- Параметр або поле, яке підлягає тестуванню і підбадають під вказані вразлвості
- Приклад payload
- Пояснення щодо того, як цей параметр або поле може бути вразливим

Метод: {parsed.get('method')}
Шлях: {parsed.get('path')}
Заголовки: {parsed.get('headers')}
Тіло: {parsed.get('body')}

Форматуй як список JSON-об’єктів:
[
  {{
    "типАтаки": "SQLi",
    "поле": "username",
    "payload": "' OR 1=1 --",
    "пояснення": "..."
  }}
]
"""

    try:
        thread = openai.beta.threads.create()
        openai.beta.threads.messages.create(
            thread_id=thread.id,
            role="user",
            content=user_prompt
        )
        run = openai.beta.threads.runs.create(
            thread_id=thread.id,
            assistant_id=ASSISTANT_ID
        )

        while True:
            run_status = openai.beta.threads.runs.retrieve(
                thread_id=thread.id,
                run_id=run.id
            )
            if run_status.status == "completed":
                break
            elif run_status.status in ["failed", "cancelled"]:
                return jsonify({"error": "Атаки не згенеровано"}), 500
            time.sleep(1)

        messages = openai.beta.threads.messages.list(thread_id=thread.id)
        answer = messages.data[0].content[0].text.value
        print("📌 Відповідь атак:\n", answer)

        cleaned = answer.strip()
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(json)?", "", cleaned)
            cleaned = re.sub(r"```$", "", cleaned)
        cleaned = cleaned.replace("“", "\"").replace("”", "\"").replace("‘", "'").replace("’", "'")

        try:
            attacks = json.loads(cleaned)
        except json.JSONDecodeError:
            attacks = [{"типАтаки": "N/A", "пояснення": answer}]

        analyzed_requests[session_id]["attacks"] = attacks

        return jsonify({
            "status": "ok",
            "sessionId": session_id,
            "attacks": attacks
        })

    except Exception as e:
        print("❌ Виникла помилка у generate_attacks:\n", traceback.format_exc())
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(port=5000)
