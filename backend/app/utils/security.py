import ipaddress, re, socket
from urllib.parse import urlparse

BLOCKED_NETWORKS = [ipaddress.ip_network(n) for n in [
    "127.0.0.0/8","10.0.0.0/8","172.16.0.0/12","192.168.0.0/16",
    "169.254.0.0/16","::1/128","fc00::/7","fe80::/10"]]

# Each tuple: (compiled pattern, replacement string)
# Patterns with a capture group use \1=[REDACTED] to preserve the key name.
# Patterns without a capture group use a plain replacement string.
SECRET_PATTERNS = [
    (re.compile(r"(?i)(aws_access_key_id|aws_secret_access_key)\s*=\s*['\"][^'\"]+"),
     r"\1=[REDACTED]"),
    (re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['\"][^'\"]{8,}"),
     r"\1=[REDACTED]"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
     "[REDACTED PRIVATE KEY HEADER]"),
]

def resolve_public_addresses(host, port):
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError("Target hostname could not be resolved") from exc
    addresses = list(dict.fromkeys(info[4][0] for info in infos))
    if not addresses:
        raise ValueError("Target hostname did not resolve to an address")
    for address in addresses:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
        if not ip.is_global or any(ip in net for net in BLOCKED_NETWORKS):
            raise ValueError("Target must resolve only to public IP addresses")
    return addresses

def is_safe_public_url(url, allowed_hosts=None):
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        return False
    host = parsed.hostname.lower()
    if allowed_hosts is not None and host not in allowed_hosts:
        return False
    try:
        resolve_public_addresses(host, parsed.port or 443)
    except ValueError:
        return False
    return True

def redact_secrets(text, max_length=240):
    text = text.strip()
    for pattern, replacement in SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    if len(text) > max_length:
        text = text[:max_length-3] + "..."
    return text
