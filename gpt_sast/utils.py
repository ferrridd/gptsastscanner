import os
import re
import logging

logger = logging.getLogger('gpt_sast.utils')

def get_language_map():
    """Return a mapping of file extensions to language names."""
    return {
        'py': 'python',
        'js': 'javascript', 
        'jsx': 'javascript',
        'ts': 'typescript',
        'tsx': 'typescript',
        'java': 'java',
        'c': 'c',
        'cpp': 'c++',
        'cs': 'csharp',
        'go': 'golang',
        'rb': 'ruby',
        'php': 'php',
        'swift': 'swift',
        'kt': 'kotlin',
        'rs': 'rust',
        'scala': 'scala',
        'sh': 'bash',
        'sql': 'sql',
        'html': 'html',
        'css': 'css',
        'xml': 'xml',
        'json': 'json',
        'yaml': 'yaml',
        'yml': 'yaml',
    }

def get_language_for_file(file_path):
    """Determine the programming language for a file based on its extension."""
    file_ext = os.path.splitext(file_path)[1][1:] if '.' in file_path else ""
    language_map = get_language_map()
    return language_map.get(file_ext, "unknown")

def get_file_context(file_path, project_context):
    """
    Get contextual information about a file to improve vulnerability detection.
    """
    file_context = {
        "frameworks": [],
        "dependencies": {},
        "purpose": "Unknown",
        "endpoints": [],
        "entry_point": False
    }
    
    # Extract filename and extension
    file_name = os.path.basename(file_path)
    file_ext = os.path.splitext(file_name)[1][1:] if '.' in file_name else ""
    
    # Get language
    language = get_language_for_file(file_path)
    
    # Copy frameworks and dependencies from project context
    if project_context:
        file_context["frameworks"] = list(project_context.get("frameworks", {}).keys())
        file_context["dependencies"] = project_context.get("dependencies", {})
        
        # Check if this is an entry point
        if file_path in project_context.get("entry_points", []):
            file_context["entry_point"] = True
    
    # Try to infer file purpose from name and path
    if "test" in file_path.lower() or "test" in file_name.lower():
        file_context["purpose"] = "Test"
    elif "controller" in file_path.lower() or "controller" in file_name.lower():
        file_context["purpose"] = "Controller"
    elif "model" in file_path.lower() or "model" in file_name.lower():
        file_context["purpose"] = "Model"
    elif "service" in file_path.lower() or "service" in file_name.lower():
        file_context["purpose"] = "Service"
    elif "repository" in file_path.lower() or "repository" in file_name.lower() or "dao" in file_path.lower():
        file_context["purpose"] = "Data Access"
    elif "api" in file_path.lower() or "rest" in file_path.lower() or "endpoint" in file_path.lower():
        file_context["purpose"] = "API Endpoint"
    elif "middleware" in file_path.lower() or "filter" in file_path.lower():
        file_context["purpose"] = "Middleware"
    elif "auth" in file_path.lower() or "security" in file_path.lower() or "login" in file_path.lower():
        file_context["purpose"] = "Authentication/Security"
    elif "util" in file_path.lower() or "helper" in file_path.lower() or "common" in file_path.lower():
        file_context["purpose"] = "Utility"
    elif "config" in file_path.lower() or "settings" in file_path.lower():
        file_context["purpose"] = "Configuration"
    
    try:
        # Try to extract more context from file content
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read(10240)  # Read first 10KB
            
            # Extract any API endpoints
            if language == "python":
                # Look for Flask/Django/FastAPI endpoints
                for match in re.finditer(r'@\w+\.route\s*\(\s*[\'"]([^\'"]+)[\'"]', content):
                    file_context["endpoints"].append(match.group(1))
            elif language in ["javascript", "typescript"]:
                # Look for Express endpoints
                for match in re.finditer(r'\.(get|post|put|delete|patch)\s*\(\s*[\'"]([^\'"]+)[\'"]', content):
                    file_context["endpoints"].append(match.group(2))
            elif language == "java":
                # Look for Spring/JAX-RS endpoints
                for match in re.finditer(r'@(RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping)\s*\(\s*[\'"]([^\'"]+)[\'"]', content):
                    file_context["endpoints"].append(match.group(2))
            
            # Check for security-related code
            security_patterns = [
                r'password', r'token', r'auth', r'crypt', r'hash', r'encrypt', r'decrypt',
                r'permission', r'role', r'admin', r'login', r'logout', r'session',
                r'jwt', r'oauth', r'csrf', r'xss', r'sql', r'injection', r'sanitize'
            ]
            
            security_matches = []
            for pattern in security_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    security_matches.append(pattern)
            
            if security_matches:
                file_context["security_relevant"] = True
                file_context["security_patterns"] = security_matches
                
                # If purpose is unknown but file has security patterns, consider it security-related
                if file_context["purpose"] == "Unknown":
                    file_context["purpose"] = "Security-Related"
    
    except Exception as e:
        logger.debug(f"Error extracting context from {file_path}: {str(e)}")
    
    return file_context

def extract_variable_from_pattern(content, pattern):
    """
    Extract variable names from a pattern in the content.
    
    Args:
        content (str): The code content to search
        pattern (str): The regex pattern with a capturing group for the variable name
    
    Returns:
        list: List of variable names found
    """
    variables = []
    for match in re.finditer(pattern, content):
        var_name = match.group(1)
        if var_name and var_name.strip():
            variables.append(var_name.strip())
    return variables

def normalize_path(path):
    """
    Normalize a file path to prevent path traversal attacks.
    """
    return os.path.normpath(os.path.abspath(path))

def get_line_for_position(content, position):
    """
    Get the line number for a position in content.
    """
    return content[:position].count('\n') + 1

def get_severity_score(vulnerability_type):
    """
    Get a severity score for a vulnerability type.
    
    Returns:
        str: 'Critical', 'High', 'Medium', or 'Low'
    """
    critical_vulns = [
        'sql_injection', 'remote_code_execution', 'command_injection',
        'deserialization', 'xxe', 'ssrf', 'authentication_bypass'
    ]
    
    high_vulns = [
        'xss', 'csrf', 'path_traversal', 'open_redirect', 'insecure_deserialization',
        'sensitive_data_exposure', 'broken_authentication', 'hard_coded_credentials',
        'weak_cryptography'
    ]
    
    medium_vulns = [
        'insecure_configuration', 'insecure_communication', 'missing_security_headers',
        'session_fixation', 'clickjacking', 'cors_misconfiguration', 'xml_injection',
        'improper_input_validation'
    ]
    
    # Normalize vulnerability type by removing spaces and converting to lowercase
    normalized_type = vulnerability_type.lower().replace(' ', '_')
    
    if any(vuln in normalized_type for vuln in critical_vulns):
        return 'Critical'
    elif any(vuln in normalized_type for vuln in high_vulns):
        return 'High'
    elif any(vuln in normalized_type for vuln in medium_vulns):
        return 'Medium'
    else:
        return 'Low'

def map_to_cwe(vulnerability_type):
    """
    Map a vulnerability type to a CWE ID.
    
    Returns:
        str: CWE ID or None if no mapping exists
    """
    cwe_map = {
        'sql_injection': 'CWE-89',
        'command_injection': 'CWE-77',
        'xss': 'CWE-79',
        'csrf': 'CWE-352',
        'path_traversal': 'CWE-22',
        'open_redirect': 'CWE-601',
        'insecure_deserialization': 'CWE-502',
        'xxe': 'CWE-611',
        'broken_authentication': 'CWE-287',
        'sensitive_data_exposure': 'CWE-200',
        'insecure_direct_object_reference': 'CWE-639',
        'security_misconfiguration': 'CWE-1021',
        'missing_function_level_access_control': 'CWE-285',
        'using_components_with_known_vulnerabilities': 'CWE-1035',
        'insecure_communication': 'CWE-319',
        'insufficient_logging_and_monitoring': 'CWE-778',
        'hard_coded_credentials': 'CWE-798',
        'weak_cryptography': 'CWE-326',
        'insecure_random': 'CWE-330',
        'race_condition': 'CWE-362',
        'buffer_overflow': 'CWE-120',
        'integer_overflow': 'CWE-190',
        'format_string': 'CWE-134',
        'prototype_pollution': 'CWE-1321',
        'nosql_injection': 'CWE-943',
        'os_command_injection': 'CWE-78',
        'code_injection': 'CWE-94',
        'ssrf': 'CWE-918',
        'ldap_injection': 'CWE-90',
        'xml_injection': 'CWE-91',
        'header_injection': 'CWE-113',
        'template_injection': 'CWE-1336'
    }
    
    # Normalize vulnerability type by removing spaces and converting to lowercase
    normalized_type = vulnerability_type.lower().replace(' ', '_')
    
    # Check for exact match
    if normalized_type in cwe_map:
        return cwe_map[normalized_type]
    
    # Check for partial match
    for key, cwe in cwe_map.items():
        if key in normalized_type or normalized_type in key:
            return cwe
    
    return None