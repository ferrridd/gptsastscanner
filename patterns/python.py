def get_patterns():
    """Python-specific vulnerability patterns."""
    return {
        "sql_injection": [
            r'cursor\.execute\s*\(\s*["\'][^"\']*\%s',
            r'cursor\.execute\s*\(\s*f["\']',
            r'cursor\.executemany\s*\(',
            r'cursor\.execute\s*\(\s*["\'][^"\']*\{',
            r'engine\.execute\s*\(',
            r'\.raw\s*\(',
            r'\.query\s*\(',
            r'\$\w+', # SQL variables in SQLAlchemy
            r'text\s*\(',
            r'select\s*\(["\'].+from',
            r'db\.session\.query'
        ],
        "command_injection": [
            r'os\.system\s*\(',
            r'subprocess\.call\s*\(',
            r'subprocess\.Popen\s*\(',
            r'exec\s*\(',
            r'eval\s*\(',
            r'os\.popen\s*\(',
            r'commands\.getoutput\s*\(',
            r'commands\.getstatusoutput\s*\(',
            r'subprocess\.check_output\s*\(',
            r'subprocess\.run\s*\(',
            r'shell\s*=\s*True'
        ],
        "xxe": [
            r'etree\.parse\s*\(',
            r'xml\.dom\.minidom\.parse\s*\(',
            r'xml\.sax\.parse\s*\(',
            r'xml\.parsers\.expat\.',
            r'lxml\.etree',
            r'ET\.parse\s*\(',
            r'parseString\s*\(',
            r'xmlrpclib\.',
            r'untrusted_xml'
        ],
        "insecure_deserialization": [
            r'pickle\.load',
            r'yaml\.load\s*\(',
            r'marshal\.load',
            r'shelve\.open',
            r'cPickle\.',
            r'jsonpickle',
            r'dill\.',
            r'pyyaml\.',
            r'unserialize\s*\(',
            r'yaml\.unsafe_load',
            r'json\.loads'
        ],
        "path_traversal": [
            r'open\s*\(\s*.*\+',
            r'open\s*\(\s*os\.path\.join',
            r'open\s*\(\s*f["\']',
            r'with\s+open\s*\(',
            r'read\s*\(',
            r'os\.path\.exists\s*\(',
            r'os\.remove\s*\(',
            r'os\.unlink\s*\(',
            r'os\.rename\s*\(',
            r'os\.path\.isfile\s*\('
        ],
        "xss": [
            r'\.get\s*\(["\'][^"\']+["\']\s*\)',
            r'request\.args',
            r'request\.form',
            r'request\.cookies',
            r'request\.headers',
            r'request\.values',
            r'request\.query_string',
            r'request\.get_json\s*\(',
            r'flask\.',
            r'django\.',
            r'render_template',
            r'mark_safe\s*\(',
            r'escape\s*\('
        ],
        "weak_crypto": [
            r'hashlib\.md5\s*\(',
            r'hashlib\.sha1\s*\(',
            r'Crypto\.Cipher',
            r'Cryptodome\.',
            r'Random\.',
            r'\.new\s*\(',
            r'secrets\.',
            r'hmac\.',
            r'AES\.new\s*\('
        ],
        "insecure_random": [
            r'random\.',
            r'\.random\s*\(',
            r'randint\s*\(',
            r'randrange\s*\(',
            r'choice\s*\(',
            r'shuffle\s*\(',
            r'sample\s*\('
        ],
        "broken_auth": [
            r'==\s*["\']+',
            r'["\']+\s*==',
            r'\.strip\s*\(\s*\)\s*==',
            r'==\s*\.strip\s*\(\s*\)',
            r'\.lower\s*\(\s*\)\s*==',
            r'==\s*\.lower\s*\(\s*\)',
            r'is\s+["\']+',
            r'["\']+\s+is',
            r'compare_digest\s*\(',
            r'check_password_hash\s*\(',
            r'pbkdf2_sha256\.',
            r'django\.contrib\.auth'
        ]
    }