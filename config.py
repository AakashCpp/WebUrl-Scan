"""
⚙️ Configuration for Web Vulnerability Scanner
"""

from pathlib import Path
from dataclasses import dataclass
from typing import List

# Paths
BASE_DIR = Path(__file__).parent
WORDLIST_DIR = BASE_DIR / "wordlists"
REPORT_DIR = BASE_DIR / "reports"
REPORT_DIR.mkdir(exist_ok=True)

@dataclass
class ScanConfig:
    """Scan configuration"""
    
    # Timeouts (seconds)
    CONNECT_TIMEOUT: int = 5
    READ_TIMEOUT: int = 10
    PORT_TIMEOUT: float = 1.0
    
    # Threading
    MAX_THREADS: int = 50
    
    # Rate limiting
    REQUEST_DELAY: float = 0.1  # Delay between requests
    
    # User agent
    USER_AGENT: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"


# Common ports to scan
COMMON_PORTS = {
    21: {"name": "FTP", "risk": "high", "description": "File Transfer Protocol"},
    22: {"name": "SSH", "risk": "medium", "description": "Secure Shell"},
    23: {"name": "Telnet", "risk": "critical", "description": "Unencrypted remote access"},
    25: {"name": "SMTP", "risk": "medium", "description": "Email server"},
    53: {"name": "DNS", "risk": "low", "description": "Domain Name System"},
    80: {"name": "HTTP", "risk": "low", "description": "Web server (unencrypted)"},
    110: {"name": "POP3", "risk": "medium", "description": "Email retrieval"},
    135: {"name": "MSRPC", "risk": "high", "description": "Microsoft RPC"},
    139: {"name": "NetBIOS", "risk": "high", "description": "Windows networking"},
    143: {"name": "IMAP", "risk": "medium", "description": "Email access"},
    443: {"name": "HTTPS", "risk": "low", "description": "Secure web server"},
    445: {"name": "SMB", "risk": "critical", "description": "Windows file sharing"},
    993: {"name": "IMAPS", "risk": "low", "description": "Secure IMAP"},
    995: {"name": "POP3S", "risk": "low", "description": "Secure POP3"},
    1433: {"name": "MSSQL", "risk": "critical", "description": "Microsoft SQL Server"},
    1521: {"name": "Oracle", "risk": "critical", "description": "Oracle Database"},
    3306: {"name": "MySQL", "risk": "critical", "description": "MySQL Database"},
    3389: {"name": "RDP", "risk": "critical", "description": "Remote Desktop"},
    5432: {"name": "PostgreSQL", "risk": "critical", "description": "PostgreSQL Database"},
    5900: {"name": "VNC", "risk": "high", "description": "Virtual Network Computing"},
    6379: {"name": "Redis", "risk": "high", "description": "Redis Database"},
    8080: {"name": "HTTP-Proxy", "risk": "medium", "description": "HTTP Proxy/Alt HTTP"},
    8443: {"name": "HTTPS-Alt", "risk": "low", "description": "Alternative HTTPS"},
    27017: {"name": "MongoDB", "risk": "critical", "description": "MongoDB Database"},
}

# Security headers to check
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "required": True,
        "description": "Enforces HTTPS connections",
        "risk_if_missing": "high"
    },
    "Content-Security-Policy": {
        "required": True,
        "description": "Prevents XSS and injection attacks",
        "risk_if_missing": "high"
    },
    "X-Frame-Options": {
        "required": True,
        "description": "Prevents clickjacking attacks",
        "risk_if_missing": "medium"
    },
    "X-Content-Type-Options": {
        "required": True,
        "description": "Prevents MIME type sniffing",
        "risk_if_missing": "medium"
    },
    "X-XSS-Protection": {
        "required": False,
        "description": "Legacy XSS protection (deprecated)",
        "risk_if_missing": "low"
    },
    "Referrer-Policy": {
        "required": True,
        "description": "Controls referrer information",
        "risk_if_missing": "low"
    },
    "Permissions-Policy": {
        "required": False,
        "description": "Controls browser features",
        "risk_if_missing": "low"
    },
    "X-Permitted-Cross-Domain-Policies": {
        "required": False,
        "description": "Controls Adobe Flash/PDF access",
        "risk_if_missing": "low"
    }
}

# Dangerous headers that shouldn't be exposed
DANGEROUS_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator"
]

# Common directories to check
COMMON_DIRECTORIES = [
    "admin", "administrator", "wp-admin", "login", "dashboard",
    "cpanel", "phpmyadmin", "adminer", "manager", "panel",
    "backup", "backups", "bak", "old", "temp", "tmp",
    "config", "configuration", "conf", "settings",
    "api", "api/v1", "api/v2", "rest", "graphql",
    "test", "testing", "dev", "development", "staging",
    "upload", "uploads", "files", "documents", "media",
    "private", "secret", "hidden", "internal",
    ".git", ".svn", ".env", ".htaccess", ".htpasswd",
    "wp-content", "wp-includes", "includes", "inc",
    "assets", "static", "css", "js", "images",
    "cgi-bin", "scripts", "bin",
    "logs", "log", "error_log", "debug",
    "db", "database", "sql", "mysql",
    "server-status", "server-info"
]

# Sensitive files to check
SENSITIVE_FILES = [
    "robots.txt", "sitemap.xml", "crossdomain.xml",
    ".git/config", ".git/HEAD", ".gitignore",
    ".env", ".env.local", ".env.production",
    "config.php", "configuration.php", "settings.php",
    "wp-config.php", "wp-config.php.bak",
    "web.config", "applicationHost.config",
    ".htaccess", ".htpasswd",
    "package.json", "composer.json", "Gemfile",
    "requirements.txt", "Pipfile",
    "phpinfo.php", "info.php", "test.php",
    "backup.zip", "backup.tar.gz", "backup.sql",
    "database.sql", "dump.sql", "db.sql",
    "id_rsa", "id_rsa.pub", ".ssh/authorized_keys",
    "server.key", "server.crt", "private.key",
    "error_log", "debug.log", "access.log"
]

# SQL Injection test payloads
SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1--",
    "\" OR 1=1--",
    "1' AND '1'='1",
    "1 AND 1=1",
    "' UNION SELECT NULL--",
    "'; DROP TABLE users--"
]

# XSS test payloads
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert('XSS')>",
    "javascript:alert('XSS')",
    "\"><script>alert('XSS')</script>",
    "'><script>alert('XSS')</script>",
    "<body onload=alert('XSS')>",
    "<iframe src=\"javascript:alert('XSS')\">",
]

# Technology signatures
TECH_SIGNATURES = {
    "WordPress": {
        "paths": ["/wp-login.php", "/wp-admin/", "/wp-content/"],
        "headers": {"X-Pingback": "xmlrpc.php"},
        "meta": ["generator.*wordpress", "wp-content", "wp-includes"]
    },
    "Joomla": {
        "paths": ["/administrator/", "/components/", "/modules/"],
        "headers": {},
        "meta": ["generator.*joomla"]
    },
    "Drupal": {
        "paths": ["/sites/default/", "/core/misc/drupal.js"],
        "headers": {"X-Generator": "Drupal"},
        "meta": ["generator.*drupal"]
    },
    "Laravel": {
        "paths": [],
        "headers": {},
        "cookies": ["laravel_session", "XSRF-TOKEN"]
    },
    "Django": {
        "paths": ["/admin/"],
        "headers": {},
        "cookies": ["csrftoken", "sessionid"]
    },
    "React": {
        "paths": [],
        "meta": ["react", "__REACT_DEVTOOLS_GLOBAL_HOOK__"]
    },
    "Angular": {
        "paths": [],
        "meta": ["ng-version", "angular"]
    },
    "Vue.js": {
        "paths": [],
        "meta": ["vue", "__VUE__"]
    }
}

print("✅ Configuration loaded!")