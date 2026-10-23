"""Positive and negative tests for SEC001, SEC002, SEC003 and CFG001."""

from __future__ import annotations

from aegisai.models.configuration import Profile
from aegisai.models.finding import Confidence, Severity
from conftest import findings_for, rule_ids, scan_code, scan_dir

FAKE_KEY = "sk-proj-FAKE0000000000000000000000000000000000000000"


# -- SEC001 ------------------------------------------------------------------------------


def test_sec001_detects_and_redacts(project) -> None:
    result = scan_code(project, f'OPENAI_API_KEY = "{FAKE_KEY}"\n', profiles=[Profile.SECRETS])
    found = findings_for(result, "SEC001")
    assert len(found) == 1
    finding = found[0]
    assert finding.location.start_line == 1
    assert finding.severity is Severity.HIGH and finding.confidence is Confidence.HIGH
    assert FAKE_KEY not in result.model_dump_json()
    assert "OPENAI_API_KEY" in finding.title


def test_sec001_env_and_yaml(project) -> None:
    root = project(
        {
            ".env": "DB_PASSWORD=Zq9kLm2p0Xy7Rt4vB1\nDEBUG=true\n",
            "config.yaml": "database:\n  password: 'Xy7Rt4vB1Zq9kLm2p0'\n  host: localhost\n",
        }
    )
    result = scan_dir(root, profiles=[Profile.SECRETS])
    assert {f.location.file_path for f in findings_for(result, "SEC001")} == {".env", "config.yaml"}


def test_sec001_negative(project) -> None:
    code = """
        import os
        api_key = os.environ["OPENAI_API_KEY"]
        password = "${DB_PASSWORD}"
        token_url = "https://example.com/oauth/token"
        secret_name = "projects/x/secrets/api"
        PASSWORD_FIELD = "password"
        max_tokens = 4096
    """
    result = scan_code(project, code, profiles=[Profile.SECRETS])
    assert findings_for(result, "SEC001") == []


def test_sec001_skips_example_files(project) -> None:
    root = project({".env.example": f"OPENAI_API_KEY={FAKE_KEY}\n"})
    assert findings_for(scan_dir(root, profiles=[Profile.SECRETS]), "SEC001") == []


# -- SEC002 ------------------------------------------------------------------------------


def test_sec002_positive(project) -> None:
    code = """
        import os, logging
        logger = logging.getLogger(__name__)

        def connect():
            password = os.environ["DB_PASSWORD"]
            logger.info("connecting with %s", password)
            print("key", os.getenv("API_KEY"))
    """
    result = scan_code(project, code, profiles=[Profile.CODE])
    found = findings_for(result, "SEC002")
    assert {f.location.start_line for f in found} == {6, 7}
    assert all(f.confidence is Confidence.HIGH for f in found)


def test_sec002_name_based_is_medium(project) -> None:
    code = """
        import logging
        def f(api_key):
            logging.debug("using %s", api_key)
    """
    found = findings_for(scan_code(project, code, profiles=[Profile.CODE]), "SEC002")
    assert len(found) == 1 and found[0].confidence is Confidence.MEDIUM and found[0].review_required


def test_sec002_negative(project) -> None:
    code = """
        import os, logging
        logger = logging.getLogger(__name__)

        def connect():
            password = os.environ["DB_PASSWORD"]
            logger.info("connected as %s", os.environ["DB_USER"])
            logger.info("password length %d", len(password))
            logger.info("tokens used: %s", os.environ["MAX_TOKENS"])
    """
    assert findings_for(scan_code(project, code, profiles=[Profile.CODE]), "SEC002") == []


# -- SEC003 ------------------------------------------------------------------------------


def test_sec003_positive_shell_true(project) -> None:
    code = """
        import subprocess
        from flask import Flask, request
        app = Flask(__name__)

        @app.route("/ping")
        def ping():
            host = request.args.get("host")
            return subprocess.check_output("ping " + host, shell=True)
    """
    found = findings_for(scan_code(project, code, profiles=[Profile.CODE]), "SEC003")
    assert len(found) == 1
    assert found[0].severity is Severity.CRITICAL
    assert found[0].location.start_line == 8
    assert any(e.kind == "sink" for e in found[0].evidence)


def test_sec003_list_argument_is_medium(project) -> None:
    code = """
        import subprocess
        from flask import request

        def ping():
            host = request.args.get("host")
            return subprocess.run(["ping", "-c", "1", host])
    """
    found = findings_for(scan_code(project, code, profiles=[Profile.CODE]), "SEC003")
    assert len(found) == 1 and found[0].severity is Severity.MEDIUM


def test_sec003_potential_dynamic_shell(project) -> None:
    code = """
        import subprocess
        def build(name):
            subprocess.run(f"make {name}", shell=True)
    """
    found = findings_for(scan_code(project, code, profiles=[Profile.CODE]), "SEC003")
    assert len(found) == 1 and found[0].confidence is Confidence.LOW and found[0].review_required


def test_sec003_negative(project) -> None:
    code = """
        import subprocess, shlex
        from flask import request
        ALLOWED = {"status", "log"}

        def ok():
            action = request.args.get("a")
            if action not in ALLOWED:
                return "no"
            subprocess.run(["git", action])
            subprocess.run("ls " + shlex.quote(request.args["p"]), shell=True)
            subprocess.run(["echo", "static"], shell=False)
    """
    assert findings_for(scan_code(project, code, profiles=[Profile.CODE]), "SEC003") == []


# -- CFG001 ------------------------------------------------------------------------------


def test_cfg001_python_patterns(project) -> None:
    code = """
        import requests, yaml, ssl
        from flask import Flask
        app = Flask(__name__)
        DEBUG = True
        ALLOWED_HOSTS = ["*"]
        requests.get("https://x", verify=False)
        yaml.load(open("c.yaml"))
        ctx = ssl._create_unverified_context()
        app.run(host="0.0.0.0", debug=True)
    """
    found = findings_for(scan_code(project, code, profiles=[Profile.CODE]), "CFG001")
    summaries = {f.evidence_summary for f in found}
    assert "DEBUG = True" in summaries
    assert 'ALLOWED_HOSTS = ["*"]' in summaries
    assert "TLS certificate verification disabled (verify=False)" in summaries
    assert "yaml.load without a safe Loader" in summaries
    assert "unverified SSL context" in summaries
    assert "debug=True in application run()" in summaries
    assert len(found) == 6


def test_cfg001_structured_patterns(project) -> None:
    root = project(
        {
            "docker-compose.yml": "services:\n  app:\n    image: x\n    privileged: true\n",
            ".github/workflows/ci.yml": "name: ci\npermissions: write-all\njobs: {}\n",
            "settings.json": '{"http": {"rejectUnauthorized": false}}',
        }
    )
    result = scan_dir(root, profiles=[Profile.CODE])
    found = findings_for(result, "CFG001")
    assert {f.location.file_path for f in found} == {
        "docker-compose.yml",
        ".github/workflows/ci.yml",
        "settings.json",
    }
    compose = next(f for f in found if f.location.file_path == "docker-compose.yml")
    assert compose.location.start_line == 4


def test_cfg001_negative(project) -> None:
    code = """
        import requests, yaml
        from flask import Flask
        app = Flask(__name__)
        DEBUG = False
        ALLOWED_HOSTS = ["app.example.com"]
        requests.get("https://x", verify="/etc/ssl/ca.pem")
        yaml.safe_load(open("c.yaml"))
        yaml.load(open("c.yaml"), Loader=yaml.SafeLoader)
        app.run(host="127.0.0.1", debug=False)
    """
    result = scan_code(project, code, profiles=[Profile.CODE])
    assert "CFG001" not in rule_ids(result)


def test_cfg001_custom_and_base_yaml_loaders_are_safe(project) -> None:
    code = """
        import yaml

        class _FrontmatterLoader(yaml.SafeLoader):
            pass

        a = yaml.load(open("a.yaml"), Loader=_FrontmatterLoader)
        b = yaml.load(open("b.yaml"), Loader=yaml.BaseLoader)
        c = yaml.load(open("c.yaml"), Loader=yaml.FullLoader)
    """
    found = findings_for(scan_code(project, code, profiles=[Profile.CODE]), "CFG001")
    assert [f.location.start_line for f in found] == [8]
