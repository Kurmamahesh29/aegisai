"""Intentionally vulnerable LLM web application used as an AegisAI fixture.

DO NOT deploy. Every weakness here is deliberate and documented in README.md.
The credentials are fake placeholders with realistic shapes so the detectors fire.
"""

import logging
import os
import subprocess

from flask import Flask, Markup, redirect, render_template_string, request
from openai import OpenAI

app = Flask(__name__)
logger = logging.getLogger(__name__)

# SEC001: hard-coded credential (fake value).
OPENAI_API_KEY = "sk-proj-FAKE0000000000000000000000000000000000000000"
client = OpenAI(api_key=OPENAI_API_KEY)
DB_PASSWORD = os.environ["DB_PASSWORD"]


@app.route("/ask", methods=["POST"])
def ask():
    question = request.form["question"]
    # LLM003: secret interpolated into the prompt.
    system_prompt = f"You are a helpful assistant. Database password: {DB_PASSWORD}"
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": question},
        ],
    )
    answer = response.choices[0].message.content
    # LLM001: LLM output executed as a shell command.
    subprocess.run(answer, shell=True)
    # LLM004: LLM output rendered as HTML.
    return render_template_string("<div>" + answer + "</div>")


@app.route("/summarize")
def summarize():
    url = request.args.get("url")
    response = client.responses.create(model="gpt-4o-mini", input=f"Summarize {url}")
    summary = response.output_text
    # SEC002: secret written to logs.
    logger.info("summary for %s using key %s", url, OPENAI_API_KEY)
    # LLM004: LLM-chosen redirect target.
    return redirect(summary)


@app.route("/render")
def render():
    prompt = request.args.get("prompt")
    completion = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": prompt}])
    html = completion.choices[0].message.content
    return Markup(html)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    # SEC003: user input reaches shell execution.
    return subprocess.check_output("ping -c 1 " + host, shell=True)


if __name__ == "__main__":
    # CFG001: debug mode on all interfaces.
    app.run(host="0.0.0.0", debug=True)
