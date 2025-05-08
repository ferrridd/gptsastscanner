import re
import logging
import os
from .utils import get_language_map

def quick_static_analysis(file_path, content):
    """
    Perform quick static analysis to identify potential issues before using GPT.
    Returns a list of potential issues found.
    """
    logger = logging.getLogger('gpt_sast.static_analyzer')
    file_ext = os.path.splitext(file_path)[1][1:] if '.' in file_path else ""
    
    language_map = get_language_map()
    language = language_map.get(file_ext, "unknown")
    
    # Import specific patterns for the detected language
    try:
        if language == "java":
            from patterns.java import get_patterns as get_java_patterns
            language_patterns = get_java_patterns()
        elif language == "python":
            from patterns.python import get_patterns as get_python_patterns
            language_patterns = get_python_patterns()
        elif language == "javascript":
            from patterns.javascript import get_patterns as get_js_patterns
            language_patterns = get_js_patterns()
        else:
            language_patterns = {}
    except ImportError:
        language_patterns = {}
    
    # Import common patterns
    try:
        from patterns.common import get_patterns as get_common_patterns
        common_patterns = get_common_patterns()
    except ImportError:
        # Fallback common patterns if import fails
        common_patterns = {
            "hardcoded_credentials": [
                r'password\s*=\s*[\'"][^\'"]+[\'"]',
                r'api[_\s]*key\s*=\s*[\'"][^\'"]+[\'"]',
                r'secret\s*=\s*[\'"][^\'"]+[\'"]',
                r'token\s*=\s*[\'"][^\'"]+[\'"]',
                r'auth\s*=\s*[\'"][^\'"]+[\'"]'
            ],
            "sensitive_info_exposure": [
                r'private\s+key',
                r'secret\s+key',
                r'BEGIN\s+PRIVATE\s+KEY',
                r'BEGIN\s+RSA\s+PRIVATE\s+KEY'
            ],
            "insecure_communication": [
                r'http://',
                r'ftp://'
            ]
        }
    
    potential_issues = []
    
    # Check common patterns
    for issue_type, patterns in common_patterns.items():
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                line_content = content.split('\n')[line_num - 1] if line_num <= len(content.split('\n')) else ""
                potential_issues.append({
                    "type": issue_type,
                    "line": line_num,
                    "pattern": pattern,
                    "content": line_content.strip()
                })
    
    # Check language-specific patterns
    for issue_type, patterns in language_patterns.items():
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                line_content = content.split('\n')[line_num - 1] if line_num <= len(content.split('\n')) else ""
                potential_issues.append({
                    "type": issue_type,
                    "line": line_num,
                    "pattern": pattern,
                    "content": line_content.strip()
                })
    
    logger.debug(f"Static analysis found {len(potential_issues)} potential issues in {file_path}")
    return potential_issues