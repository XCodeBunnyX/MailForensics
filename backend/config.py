"""
GmailGuard — Central Configuration
All weights, thresholds, and toggles are here.
No business-logic code imports this as a module; it is imported directly.
"""

# ──────────────────────────────────────────────
# SIGNAL WEIGHTS  (must sum to 1.0)
# ──────────────────────────────────────────────
SIGNAL_WEIGHTS: dict[str, float] = {
    "ml":             0.30,   # NLP / SVM classifier
    "authentication": 0.20,   # SPF + DKIM + DMARC combined
    "url":            0.20,   # URL feature analysis
    "ip":             0.10,   # IP reputation & ASN
    "domain":         0.10,   # Domain intelligence
    "attachment":     0.10,   # Static attachment analysis
}

# ──────────────────────────────────────────────
# AUTHENTICATION SUB-WEIGHTS  (within the 0.20 block)
# ──────────────────────────────────────────────
AUTH_SUB_WEIGHTS: dict[str, float] = {
    "spf":   1 / 3,
    "dkim":  1 / 3,
    "dmarc": 1 / 3,
}

# ──────────────────────────────────────────────
# VERDICT THRESHOLDS
# ──────────────────────────────────────────────
VERDICT_THRESHOLDS: list[tuple[int, str]] = [
    (85, "CRITICAL"),
    (70, "HIGH_RISK"),
    (50, "MEDIUM_RISK"),
    (25, "LOW_RISK"),
    (0,  "CLEAN"),
]

# ──────────────────────────────────────────────
# AUTHENTICATION SCORE MAP
# PASS → low sub-score (good)  FAIL → high sub-score (bad)
# NONE/UNKNOWN → neutral (treated as missing info, not malicious)
# ──────────────────────────────────────────────
AUTH_SCORE_MAP: dict[str, int] = {
    "PASS":    10,    # low risk contribution
    "FAIL":    90,    # high risk contribution
    "SOFTFAIL": 60,
    "NONE":    50,    # neutral
    "UNKNOWN": 50,    # neutral
    "NEUTRAL": 45,
    "PERMERROR": 65,
    "TEMPERROR": 55,
}

# ──────────────────────────────────────────────
# ML CLASSIFIER
# ──────────────────────────────────────────────
ML_MODEL_PATH      = "models/gmailguard_svm.pkl"
ML_VECTORIZER_PATH = "models/gmailguard_tfidf.pkl"

# Decision score → raw sub-score mapping
# LinearSVC decision scores are unbounded; we clip and rescale.
ML_DECISION_SCORE_CLIP = 3.0   # absolute clip value

# ──────────────────────────────────────────────
# URL ANALYSIS
# ──────────────────────────────────────────────
SUSPICIOUS_TLDS = {
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq",  # free TLDs abused heavily
    ".top", ".work", ".click", ".download", ".link",
    ".zip", ".mov",   # recently released, often abused
    ".info", ".biz",  # historically abused
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "buff.ly", "is.gd", "rb.gy", "shorte.st", "adf.ly",
    "cutt.ly", "short.io", "tiny.cc", "clck.ru",
}

MAX_SUBDOMAINS_ALLOWED = 4      # ≥ this → suspicious
SUSPICIOUS_CHAR_PATTERNS = [
    "@",         # @ in URL path — credential phishing trick
    "%00",       # null byte
    "//",        # double slash (after scheme)
]

# ──────────────────────────────────────────────
# ATTACHMENT ANALYSIS
# ──────────────────────────────────────────────
DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".com", ".pif", ".scr", ".vbs",
    ".vbe", ".js", ".jse", ".ws", ".wsf", ".wsc", ".wsh", ".ps1",
    ".ps1xml", ".ps2", ".ps2xml", ".psc1", ".psc2", ".msh", ".msh1",
    ".msh2", ".mshxml", ".msh1xml", ".msh2xml", ".lnk", ".inf",
    ".reg", ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam",
    ".jar", ".hta", ".cpl", ".msi", ".msp", ".gadget", ".application",
    ".appx", ".iso", ".img",
}

ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".cab"}

MACRO_INDICATOR_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam"}

SUSPICIOUS_FILENAME_KEYWORDS = [
    "invoice", "payment", "urgent", "confidential", "bank", "account",
    "verify", "suspended", "password", "update", "receipt", "delivery",
]

MAX_SAFE_ATTACHMENT_SIZE_MB = 25

# ──────────────────────────────────────────────
# IP INTELLIGENCE
# ──────────────────────────────────────────────
# Private / reserved ranges — ignore these
PRIVATE_IP_NETWORKS = [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "169.254.0.0/16", "::1/128",
    "fc00::/7", "fe80::/10", "0.0.0.0/8", "100.64.0.0/10",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
    "240.0.0.0/4", "255.255.255.255/32",
]

# ──────────────────────────────────────────────
# GEOLOCATION
# ──────────────────────────────────────────────
# Free API — no key required; rate limit: 45 req/min
GEOLOCATION_API_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,isp,org,as"
GEOLOCATION_TIMEOUT_S = 5
# Set to True to use the live API; False uses mock/offline mode
GEOLOCATION_LIVE = False

# ──────────────────────────────────────────────
# REPUTATION PROVIDERS  (pluggable later)
# ──────────────────────────────────────────────
USE_LIVE_IP_REPUTATION     = False   # plug in VirusTotal / AbuseIPDB etc.
USE_LIVE_DOMAIN_REPUTATION = False   # plug in VirusTotal / Whois etc.

# ──────────────────────────────────────────────
# IMPACT LABEL THRESHOLDS  (for evidence items)
# ──────────────────────────────────────────────
EVIDENCE_IMPACT_HIGH   = 70   # sub-score ≥ this → HIGH impact
EVIDENCE_IMPACT_MEDIUM = 40   # sub-score ≥ this → MEDIUM impact
                               # below → LOW impact
