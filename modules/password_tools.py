import hashlib
import base64
import secrets
import string
import re
from datetime import datetime

ROCKYOU_MINI = [
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
    "letmein", "trustno1", "dragon", "baseball", "iloveyou", "master",
    "sunshine", "ashley", "bailey", "passw0rd", "shadow", "123123", "654321",
    "superman", "qazwsx", "michael", "football", "password1", "password123",
    "admin", "welcome", "login", "hello", "charlie", "donald", "pass",
    "qwerty123", "solo", "starwars", "master123", "admin123", "root",
    "test", "guest", "user", "demo", "changeme", "default", "temp",
    "1q2w3e4r", "qwertyuiop", "1234567890", "0987654321",
]

HASH_PATTERNS = {
    "MD5":     (r'^[a-f0-9]{32}$', 32),
    "SHA-1":   (r'^[a-f0-9]{40}$', 40),
    "SHA-256": (r'^[a-f0-9]{64}$', 64),
    "SHA-512": (r'^[a-f0-9]{128}$', 128),
    "SHA-384": (r'^[a-f0-9]{96}$', 96),
    "NTLM":    (r'^[a-f0-9]{32}$', 32),
    "bcrypt":  (r'^\$2[aby]\$\d{2}\$.{53}$', None),
    "MD5-crypt": (r'^\$1\$.+\$.+$', None),
    "SHA-512-crypt": (r'^\$6\$.+\$.+$', None),
    "Base64":  (r'^[A-Za-z0-9+/]+=*$', None),
}


def identify_hash(h: str) -> dict:
    result = {"hash": h, "timestamp": datetime.utcnow().isoformat(), "possible_types": []}
    length = len(h)

    for htype, (pattern, expected_len) in HASH_PATTERNS.items():
        try:
            if re.match(pattern, h, re.IGNORECASE):
                confidence = "High" if expected_len and length == expected_len else "Medium"
                result["possible_types"].append({"type": htype, "confidence": confidence})
        except Exception:
            pass

    if not result["possible_types"]:
        result["possible_types"].append({"type": "Unknown", "confidence": "Low"})

    return result


def _hash_word(word: str, method: str) -> str:
    w = word.encode()
    if method == "md5":
        return hashlib.md5(w).hexdigest()
    elif method == "sha1":
        return hashlib.sha1(w).hexdigest()
    elif method == "sha256":
        return hashlib.sha256(w).hexdigest()
    elif method == "sha512":
        return hashlib.sha512(w).hexdigest()
    elif method == "ntlm":
        import hashlib
        return hashlib.new("md4", word.encode("utf-16-le")).hexdigest()
    return ""


def crack_hash(h: str, method: str = "md5") -> dict:
    result = {"hash": h, "method": method, "timestamp": datetime.utcnow().isoformat(), "cracked": False}
    h_lower = h.lower()

    for word in ROCKYOU_MINI:
        candidate = _hash_word(word, method)
        if candidate == h_lower:
            result["cracked"] = True
            result["plaintext"] = word
            result["note"] = "Found in built-in mini wordlist"
            return result

    result["note"] = "Not found in built-in wordlist. For full cracking use hashcat or john with rockyou.txt"
    return result


def generate_password(length: int = 16, options: dict = None) -> dict:
    if options is None:
        options = {}

    charset = ""
    if options.get("uppercase", True):
        charset += string.ascii_uppercase
    if options.get("lowercase", True):
        charset += string.ascii_lowercase
    if options.get("digits", True):
        charset += string.digits
    if options.get("symbols", True):
        charset += "!@#$%^&*()_+-=[]{}|;:,.<>?"

    if not charset:
        charset = string.ascii_letters + string.digits

    length = max(8, min(128, length))
    password = "".join(secrets.choice(charset) for _ in range(length))

    entropy = len(charset) ** length
    import math
    bits = math.log2(entropy) if entropy > 0 else 0

    return {
        "password": password,
        "length": length,
        "charset_size": len(charset),
        "entropy_bits": round(bits, 1),
        "strength": "Very Strong" if bits > 80 else "Strong" if bits > 60 else "Medium" if bits > 40 else "Weak",
    }


def encode_decode(text: str, method: str = "base64", action: str = "encode") -> dict:
    result = {"input": text, "method": method, "action": action, "timestamp": datetime.utcnow().isoformat()}

    try:
        if method == "base64":
            if action == "encode":
                result["output"] = base64.b64encode(text.encode()).decode()
            else:
                result["output"] = base64.b64decode(text).decode(errors="replace")

        elif method == "base32":
            if action == "encode":
                result["output"] = base64.b32encode(text.encode()).decode()
            else:
                result["output"] = base64.b32decode(text.upper()).decode(errors="replace")

        elif method == "hex":
            if action == "encode":
                result["output"] = text.encode().hex()
            else:
                result["output"] = bytes.fromhex(text).decode(errors="replace")

        elif method == "url":
            from urllib.parse import quote, unquote
            if action == "encode":
                result["output"] = quote(text)
            else:
                result["output"] = unquote(text)

        elif method == "html":
            import html
            if action == "encode":
                result["output"] = html.escape(text)
            else:
                result["output"] = html.unescape(text)

        elif method == "rot13":
            result["output"] = text.translate(str.maketrans(
                'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
            ))

        elif method in ("md5", "sha1", "sha256", "sha512"):
            func = getattr(hashlib, method)
            result["output"] = func(text.encode()).hexdigest()
            result["note"] = "Hash is one-way, decode not possible"

        else:
            result["error"] = f"Unknown method: {method}"

    except Exception as e:
        result["error"] = str(e)

    return result
