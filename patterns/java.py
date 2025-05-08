def get_patterns():
    """Java-specific vulnerability patterns."""
    return {
        "sql_injection": [
            r'executeQuery\s*\(\s*["\']SELECT',
            r'createStatement\s*\(\s*\)',
            r'prepareStatement\s*\(\s*"[^"]*(SELECT|INSERT|UPDATE|DELETE)',
            r'Statement\s*.*\s*=\s*.*\.createStatement\s*\(\s*\)',
            r'executeUpdate\s*\(\s*["\']',
            r'execute\s*\(\s*["\']'
        ],
        "command_injection": [
            r'Runtime\.getRuntime\(\)\.exec\(',
            r'ProcessBuilder\(',
            r'new\s+ProcessBuilder\(',
            r'Process\s*',
            r'\.start\(',
            r'\.exec\('
        ],
        "xxe": [
            r'DocumentBuilderFactory',
            r'SAXParserFactory',
            r'XMLReader',
            r'TransformerFactory',
            r'SAXBuilder',
            r'SAXParser',
            r'XMLInputFactory',
            r'SchemaFactory',
            r'ValidationDriver'
        ],
        "insecure_deserialization": [
            r'ObjectInputStream',
            r'readObject\(',
            r'Serializable',
            r'XMLDecoder',
            r'readValue\(',
            r'fromXML\(',
            r'readResolve\(',
            r'readExternal\('
        ],
        "path_traversal": [
            r'new\s+File\s*\(\s*.*\+',
            r'new\s+FileInputStream\s*\(\s*.*\+',
            r'new\s+FileOutputStream\s*\(\s*.*\+',
            r'new\s+RandomAccessFile\s*\(\s*.*\+',
            r'Paths\.get\s*\(\s*.*\+'
        ],
        "xss": [
            r'getParameter\s*\(\s*["\'][^"\']+["\']\s*\)',
            r'getHeader\s*\(\s*["\'][^"\']+["\']\s*\)',
            r'getCookie\s*\(\s*["\'][^"\']+["\']\s*\)',
            r'setAttribute\s*\(\s*["\'][^"\']+["\']\s*,',
            r'getQueryString\s*\(\s*\)'
        ],
        "weak_crypto": [
            r'getInstance\s*\(\s*["\'](DES|RC2|RC4|Blowfish|AES/ECB)["\']',
            r'DESKeySpec',
            r'IvParameterSpec\s*\(\s*.{1,10}\s*\)',
            r'Cipher\.ENCRYPT_MODE',
            r'MessageDigest\.getInstance\s*\(\s*["\'](MD5|SHA1)["\']'
        ],
        "insecure_random": [
            r'new\s+Random\s*\(',
            r'Math\.random\s*\(',
            r'java\.util\.Random',
            r'nextInt\s*\(',
            r'nextDouble\s*\(',
            r'nextBytes\s*\('
        ],
        "broken_auth": [
            r'equals\s*\(',
            r'\.equals\s*\(',
            r'==\s*["\']+',
            r'["\']+\s*==',
            r'\.equalsIgnoreCase\s*\(',
            r'\.contentEquals\s*\(',
            r'\.compareTo\s*\('
        ]
    }