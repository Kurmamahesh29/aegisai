"""Secure counterpart of vulnerable-llm-app. Should produce no AegisAI findings."""

import logging
import os
import subprocess

from flask import Flask, jsonify, request
from openai import OpenAI
from pydantic import BaseModel

app = Flask(__name__)
logger = logging.getLogger(__name__)
client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

ALLOWED_COMMANDS = {"status": ["git", "status"], "log": ["git", "log", "-1"]}


class Decision(BaseModel):
    action: str
    reason: str


@app.route("/ask", methods=["POST"])
def ask():
    question = request.form["question"]
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "system", "content": "You are a helpful assistant."}, {"role": "user", "content": question}],
    )
    answer = response.choices[0].message.content
    # Model output is returned as JSON data, never executed or rendered as HTML.
    return jsonify({"answer": answer})


@app.route("/action", methods=["POST"])
def action():
    response = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": request.form["q"]}])
    decision = Decision.model_validate_json(response.choices[0].message.content)
    # Allow-listed dispatch: the model picks a key, never a command string.
    command = ALLOWED_COMMANDS.get(decision.action)
    if command is None:
        return jsonify({"error": "unknown action"}), 400
    output = subprocess.run(command, capture_output=True, text=True, check=False)
    logger.info("ran action %s", decision.action)
    return jsonify({"output": output.stdout})


if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=False)
