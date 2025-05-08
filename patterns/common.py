def get_patterns():
    """Common vulnerability patterns that apply to most languages."""
    return {
        "hardcoded_credentials": [
            r'password\s*=\s*[\'"][^\'"]+[\'"]',
            r'api[_\s]*key\s*=\s*[\'"][^\'"]+[\'"]',
            r'secret\s*=\s*[\'"][^\'"]+[\'"]',
            r'token\s*=\s*[\'"][^\'"]+[\'"]',
            r'auth\s*=\s*[\'"][^\'"]+[\'"]',
            r'credentials\s*=\s*[\'"][^\'"]+[\'"]',
            r'passwd\s*=\s*[\'"][^\'"]+[\'"]'
        ],
        "sensitive_info_exposure": [
            r'private\s+key',
            r'secret\s+key',
            r'BEGIN\s+PRIVATE\s+KEY',
            r'BEGIN\s+RSA\s+PRIVATE\s+KEY',
            r'ssh-rsa',
            r'access_token',
            r'refresh_token',
            r'authorization:\s*bearer',
            r'eyJ[a-zA-Z0-9_-]{5,}\.eyJ[a-zA-Z0-9_-]{5,}' # JWT pattern
        ],
        "insecure_communication": [
            r'http://',
            r'ftp://',
            r'telnet://',
            r'allowUnsafeEval',
            r'allowSelfSignedCert',
            r'validateCertificate\s*=\s*false',
            r'InsecureSkipVerify\s*:\s*true',
            r'ALLOW_INSECURE'
        ],
        "dangerous_functions": [
            r'md5\(',
            r'sha1\(',
            r'random\(',
            r'Math\.random\(',
            r'srand\(',
            r'sleep\(',
            r'setTimeout\(',
            r'setInterval\('
        ]
    }