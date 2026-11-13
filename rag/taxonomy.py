"""Bang phan loai lo hong dung lam metadata cho Knowledge Base.

Ten `vuln_type` duoc dat trung voi ten skill co san cua Strix
(strix/skills/vulnerabilities/*.md) de de doi chieu khi danh gia.
Moi loai gom: tu khoa nhan dien (khop theo ranh gioi tu tren tieu de tai lieu),
danh sach CWE lien quan va hang muc OWASP Top 10 (2021).
"""

from __future__ import annotations

import re

VULN_TYPES: dict[str, dict] = {
    "sql_injection": {
        "keywords": ["sql injection", "query parameterization", "sqli"],
        "cwe": [89, 564],
        "top10": "A03:2021-Injection",
    },
    "nosql_injection": {
        "keywords": ["nosql"],
        "cwe": [943],
        "top10": "A03:2021-Injection",
    },
    "xss": {
        "keywords": ["cross site scripting", "cross-site scripting", "xss", "dom based", "content security policy"],
        "cwe": [79, 80, 83, 87],
        "top10": "A03:2021-Injection",
    },
    "rce": {
        "keywords": ["command injection", "os command", "code injection", "remote code"],
        "cwe": [77, 78, 94, 95],
        "top10": "A03:2021-Injection",
    },
    "ssti": {
        "keywords": ["template injection", "ssti"],
        "cwe": [1336],
        "top10": "A03:2021-Injection",
    },
    "xxe": {
        "keywords": ["xml external entity", "xxe", "xml security", "xml injection"],
        "cwe": [611, 776, 91],
        "top10": "A05:2021-Security Misconfiguration",
    },
    "ldap_xpath_injection": {
        "keywords": ["ldap injection", "xpath injection", "ldap"],
        "cwe": [90, 643],
        "top10": "A03:2021-Injection",
    },
    "csrf": {
        "keywords": ["cross-site request forgery", "cross site request forgery", "csrf"],
        "cwe": [352],
        "top10": "A01:2021-Broken Access Control",
    },
    "ssrf": {
        "keywords": ["server side request forgery", "server-side request forgery", "ssrf"],
        "cwe": [918],
        "top10": "A10:2021-Server-Side Request Forgery",
    },
    "path_traversal_lfi_rfi": {
        "keywords": ["path traversal", "directory traversal", "file inclusion"],
        "cwe": [22, 23, 35, 73, 98],
        "top10": "A01:2021-Broken Access Control",
    },
    "insecure_file_uploads": {
        "keywords": ["file upload"],
        "cwe": [434],
        "top10": "A04:2021-Insecure Design",
    },
    "authentication": {
        "keywords": ["authentication", "multifactor", "credential stuffing", "forgot password",
                     "password storage", "brute force", "account lockout"],
        "cwe": [287, 306, 307, 640, 798, 1390],
        "top10": "A07:2021-Identification and Authentication Failures",
    },
    "authentication_jwt": {
        "keywords": ["json web token", "jwt"],
        "cwe": [345, 347, 1270],
        "top10": "A07:2021-Identification and Authentication Failures",
    },
    "weak_password_detection": {
        "keywords": ["weak password", "password policy", "default credentials"],
        "cwe": [521, 1391],
        "top10": "A07:2021-Identification and Authentication Failures",
    },
    "session_management": {
        "keywords": ["session management", "session fixation", "session timeout", "cookie"],
        "cwe": [384, 613, 614, 1004, 565],
        "top10": "A07:2021-Identification and Authentication Failures",
    },
    "idor": {
        "keywords": ["insecure direct object reference", "idor", "bola"],
        "cwe": [639],
        "top10": "A01:2021-Broken Access Control",
    },
    "broken_function_level_authorization": {
        "keywords": ["authorization", "access control", "privilege escalation", "function level"],
        "cwe": [284, 285, 862, 863, 269],
        "top10": "A01:2021-Broken Access Control",
    },
    "mass_assignment": {
        "keywords": ["mass assignment"],
        "cwe": [915],
        "top10": "A08:2021-Software and Data Integrity Failures",
    },
    "open_redirect": {
        "keywords": ["unvalidated redirect", "open redirect", "redirects and forwards"],
        "cwe": [601],
        "top10": "A01:2021-Broken Access Control",
    },
    "cors": {
        "keywords": ["cors", "cross-origin resource sharing", "cross origin resource sharing"],
        "cwe": [942, 346],
        "top10": "A05:2021-Security Misconfiguration",
    },
    "security_headers": {
        "keywords": ["http headers", "security headers", "strict transport security", "hsts",
                     "clickjacking", "response headers"],
        "cwe": [693, 1021, 16],
        "top10": "A05:2021-Security Misconfiguration",
    },
    "information_disclosure": {
        "keywords": ["error handling", "information disclosure", "information leakage", "fingerprint"],
        "cwe": [200, 209, 497, 532, 538, 548],
        "top10": "A05:2021-Security Misconfiguration",
    },
    "insecure_deserialization": {
        "keywords": ["deserialization", "serialization"],
        "cwe": [502],
        "top10": "A08:2021-Software and Data Integrity Failures",
    },
    "http_request_smuggling": {
        "keywords": ["request smuggling", "http smuggling"],
        "cwe": [444],
        "top10": "A05:2021-Security Misconfiguration",
    },
    "header_injection": {
        "keywords": ["header injection", "response splitting", "host header", "crlf"],
        "cwe": [93, 113, 644],
        "top10": "A03:2021-Injection",
    },
    "prototype_pollution": {
        "keywords": ["prototype pollution"],
        "cwe": [1321],
        "top10": "A08:2021-Software and Data Integrity Failures",
    },
    "race_conditions": {
        "keywords": ["race condition", "race conditions", "toctou"],
        "cwe": [362, 367],
        "top10": "A04:2021-Insecure Design",
    },
    "business_logic": {
        "keywords": ["business logic", "abuse case", "transaction authorization"],
        "cwe": [840, 841],
        "top10": "A04:2021-Insecure Design",
    },
    "cryptography": {
        "keywords": ["cryptographic", "cryptography", "transport layer security", "tls",
                     "key management", "pinning", "secrets management"],
        "cwe": [319, 326, 327, 328, 311, 312, 916],
        "top10": "A02:2021-Cryptographic Failures",
    },
    "api_security": {
        "keywords": ["rest security", "rest assessment", "graphql", "api testing", "web service", "grpc"],
        "cwe": [],
        "top10": "",
    },
    "vulnerable_components": {
        "keywords": ["vulnerable dependency", "dependency", "third party javascript", "software supply chain",
                     "npm security", "virtual patching"],
        "cwe": [1104, 1395],
        "top10": "A06:2021-Vulnerable and Outdated Components",
    },
    "logging_monitoring": {
        "keywords": ["logging", "monitoring"],
        "cwe": [778, 117, 223],
        "top10": "A09:2021-Security Logging and Monitoring Failures",
    },
    "llm_prompt_injection": {
        "keywords": ["prompt injection", "llm", "ai agent", "large language model"],
        "cwe": [1427],
        "top10": "",
    },
}

_CWE_TO_TYPES: dict[int, list[str]] = {}
for _name, _info in VULN_TYPES.items():
    for _cwe in _info["cwe"]:
        _CWE_TO_TYPES.setdefault(_cwe, []).append(_name)

_KW_PATTERNS = {
    name: [re.compile(r"(?<![a-z0-9])" + re.escape(kw) + r"(?![a-z0-9])") for kw in info["keywords"]]
    for name, info in VULN_TYPES.items()
}


def normalize(text: str) -> str:
    return re.sub(r"[_\s]+", " ", text).lower()


def classify_title(title: str) -> list[str]:
    """Gan vuln_type theo tieu de / ten file tai lieu."""
    text = normalize(title)
    return [name for name, pats in _KW_PATTERNS.items() if any(p.search(text) for p in pats)]


def types_for_cwe(cwe_id: int) -> list[str]:
    return list(_CWE_TO_TYPES.get(cwe_id, []))


def top10_for_types(types: list[str]) -> list[str]:
    return sorted({VULN_TYPES[t]["top10"] for t in types if VULN_TYPES[t]["top10"]})


def parse_cwe(value: object) -> int | None:
    if value is None:
        return None
    m = re.search(r"(\d+)", str(value))
    return int(m.group(1)) if m else None
