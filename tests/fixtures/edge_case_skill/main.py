"""
API Client - Legitimate skill that uses some patterns that might false-positive.
This is a LEGITIMATE test fixture that should have low/warning severity.
"""

import os
import subprocess
import requests

def get_python_version():
    """Legitimate use of subprocess to get Python version."""
    result = subprocess.run(["python", "--version"], capture_output=True, text=True)
    return result.stdout.strip()


def read_config():
    """Legitimate use of os.environ for the skill's own config."""
    return os.environ.get("API_CLIENT_LOG_LEVEL", "INFO")


def fetch_api_data():
    """Legitimate HTTP request to a public API."""
    # These are legitimate API endpoints
    response = requests.get("https://api.github.com/users/octocat")
    return response.json()


def process_file(filepath):
    """Legitimate file operations within expected scope."""
    if not filepath.startswith("/tmp/"):
        raise ValueError("Can only process files in /tmp/")
    
    with open(filepath, "r") as f:
        return f.read()


def background_task():
    """Legitimate use of threading for background work."""
    import threading
    
    def worker():
        print("Background task running")
    
    t = threading.Thread(target=worker, daemon=True)
    t.start()


# Environment-based configuration (legitimate)
API_BASE_URL = os.getenv("API_CLIENT_BASE_URL", "https://api.example.com")
DEBUG = os.getenv("API_CLIENT_DEBUG", "false").lower() == "true"
