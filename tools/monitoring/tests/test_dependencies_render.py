"""dependencies-render's command (nc8kg1101/monitoring/prometheus/service.yaml), run against the committed template."""
import os
import subprocess
import sys
from pathlib import Path

import yaml

PROMETHEUS_DIR = Path(__file__).resolve().parents[3] / "nc8kg1101" / "monitoring" / "prometheus"


def service():
    compose = yaml.safe_load((PROMETHEUS_DIR / "service.yaml").read_text())
    return compose["services"]["dependencies-render"]


def service_env(svc):
    env = svc.get("environment") or {}
    if isinstance(env, list):
        env = dict(item.split("=", 1) for item in env)
    return {k: str(v) for k, v in env.items()}


def test_renders_the_committed_template(tmp_path):
    svc = service()
    assert svc["command"][:2] == ["python3", "-c"]
    # The container's paths, mapped into tmp_path; signal.pause() would block forever.
    script = (
        svc["command"][2]
        .replace("/etc/dependencies.yml", str(PROMETHEUS_DIR / "dependencies.yml"))
        .replace("/tmp/", f"{tmp_path}/")
        .replace("signal.pause()", "pass")
    )
    # Only the Service's own environment, plus PATH for the interpreter.
    env = {"PATH": os.environ.get("PATH", ""), **service_env(svc)}
    result = subprocess.run([sys.executable, "-c", script], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "rendered dependencies.yml" in result.stdout
    rendered = yaml.safe_load((tmp_path / "dependencies.yml").read_text())
    assert isinstance(rendered, list)
