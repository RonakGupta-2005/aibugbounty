from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
SRC_DIR = BASE_DIR / "src"
OUTPUTS_DIR = BASE_DIR / "outputs"
MODELS_DIR = BASE_DIR / "models"

OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR.mkdir(parents=True, exist_ok=True)
REQUEST_DELAY = 0.05
TIMEOUT = 6
DELAY_THRESHOLD = 4
CONCURRENCY = 10

HEADERS = {
    "User-Agent": "Mozilla/5.0 (SmartScannerV6-Modular)",
    "Content-Type": "application/json",
}

SUBDOMAIN_FILE = OUTPUTS_DIR / "subdomains.txt"
CRT_FILE = OUTPUTS_DIR / "crtsh_subdomains.txt"
PRIORITIZED_FILE = OUTPUTS_DIR / "prioritized_subdomains.txt"

ENDPOINT_FILE = OUTPUTS_DIR / "discovered_endpoints.txt"
LEGACY_ENDPOINTS_FILE = OUTPUTS_DIR / "endpoints.txt"
JS_ENDPOINT_FILE = OUTPUTS_DIR / "js_discovered_endpoints.txt"
PARAMETER_FILE = OUTPUTS_DIR / "discovered_parameters.txt"
API_FILE = OUTPUTS_DIR / "api_endpoints.txt"

REPORT_FILE = OUTPUTS_DIR / "final_report.json"
HUMAN_REPORT = OUTPUTS_DIR / "bug_bounty_report.txt"

MODEL_PATH = MODELS_DIR / "vulnerability_detector.pkl"

COMMON_PARAMS = ["id", "userId", "account", "uid", "page", "item", "user", "token"]
TEST_VALUES = ["1", "2", "3", "999", "admin", "true"]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE"]

PAYLOADS = {
    "xss": ["<script>alert(1)</script>"],
    "sqli": ["' OR SLEEP(5)--"],
}

SENSITIVE_KEYS = [
    "email",
    "username",
    "password",
    "token",
    "address",
    "phone",
]

SECRET_PATTERNS = [
    r'api[_-]?key["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-]{16,}',
    r"Bearer\s+[A-Za-z0-9\-_\.]+",
    r"AIza[0-9A-Za-z\-_]{35}",
]

LOW_VALUE_ENDPOINTS = ["captcha", "health", "status", "login", "2fa", "chatbot"]

ERROR_PATTERNS = [
    "unexpected path",
    "error:",
    "not found",
    "invalid",
    "cannot",
]