import os
import re
import json
import logging
from .utils import get_language_map

logger = logging.getLogger('gpt_sast.file_manager')

def get_project_structure(project_path, ignore_patterns=None, max_file_size=100000, max_files=None):
    """
    Get the structure of the project files with improved filtering.
    Returns a nested dictionary representing the project structure.
    """
    structure = {}
    file_count = 0
    max_files_limit = max_files or 1000  # Default to 1000 if not specified
    language_map = get_language_map()
    
    # Default ignore patterns if none provided
    if ignore_patterns is None:
        ignore_patterns = [
            r'\.git', r'\.svn', r'\.hg', r'\.bzr',
            r'node_modules', r'venv', r'__pycache__', r'env',
            r'dist', r'build', r'target', r'out', r'output',
            r'\.pyc$', r'\.min\.js$', r'\.min\.css$', r'\.bundle\.js$',
            r'\.jpg$', r'\.jpeg$', r'\.png$', r'\.gif$', r'\.ico$', r'\.svg$',
            r'\.pdf$', r'\.zip$', r'\.tar$', r'\.gz$', r'\.rar$', r'\.exe$'
        ]
    
    # Compile regex patterns
    ignore_regex = [re.compile(pattern) for pattern in ignore_patterns]
    
    for root, dirs, files in os.walk(project_path):
        # Skip directories matching ignore patterns
        dirs[:] = [d for d in dirs if not any(pattern.search(d) for pattern in ignore_regex)]
        
        rel_path = os.path.relpath(root, project_path)
        if rel_path == ".":
            rel_path = ""
        
        # Skip if the relative path matches any ignore pattern
        if any(pattern.search(rel_path) for pattern in ignore_regex):
            continue
        
        path_parts = rel_path.split(os.sep) if rel_path else []
        current = structure
        
        # Build directory structure
        for part in path_parts:
            if part not in current:
                current[part] = {}
            current = current[part]
        
        # Add files
        for file in files:
            # Skip if file matches any ignore pattern
            if any(pattern.search(file) for pattern in ignore_regex):
                continue
            
            file_path = os.path.join(root, file)
            
            # Get file extension
            file_ext = os.path.splitext(file)[1][1:] if '.' in file else ""
            
            # Focus on source code files
            if file_ext in language_map:
                try:
                    file_size = os.path.getsize(file_path)
                    
                    # Skip files that are too large
                    if file_size > max_file_size:
                        continue
                    
                    file_info = {
                        "type": file_ext,
                        "size": file_size,
                        "language": language_map.get(file_ext, "unknown")
                    }
                    
                    # Add file metadata
                    try:
                        add_file_metadata(file_path, file_info)
                    except Exception as e:
                        logger.debug(f"Error getting metadata for {file_path}: {str(e)}")
                    
                    current[file] = file_info
                    
                    file_count += 1
                    if file_count >= max_files_limit:
                        logger.info(f"Reached maximum file limit ({max_files_limit})")
                        return structure
                except Exception as e:
                    logger.debug(f"Error processing file {file_path}: {str(e)}")
    
    return structure

def add_file_metadata(file_path, file_info):
    """Add additional metadata about the file based on its content."""
    try:
        # Limit file reading to first 10KB for performance
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read(10240)
            
        # Look for imports/dependencies
        imports = extract_imports(content, file_info.get("language", "unknown"))
        if imports:
            file_info["imports"] = imports
        
        # Look for API endpoints
        endpoints = extract_endpoints(content, file_info.get("language", "unknown"))
        if endpoints:
            file_info["endpoints"] = endpoints
        
        # Look for security-critical functions
        critical_functions = extract_critical_functions(content, file_info.get("language", "unknown"))
        if critical_functions:
            file_info["critical_functions"] = critical_functions
            
    except Exception as e:
        logger.debug(f"Error in add_file_metadata for {file_path}: {str(e)}")

def extract_imports(content, language):
    """Extract imports or dependencies from file content."""
    imports = []
    
    if language == "python":
        # Extract Python imports
        import_patterns = [
            r'import\s+(\w+(?:\.\w+)*)',
            r'from\s+(\w+(?:\.\w+)*)\s+import'
        ]
        
        for pattern in import_patterns:
            for match in re.finditer(pattern, content):
                imports.append(match.group(1))
    
    elif language in ["javascript", "typescript"]:
        # Extract JS/TS imports
        import_patterns = [
            r'import\s+.*\s+from\s+[\'"]([^\'"]+)[\'"]',
            r'require\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)'
        ]
        
        for pattern in import_patterns:
            for match in re.finditer(pattern, content):
                imports.append(match.group(1))
    
    elif language == "java":
        # Extract Java imports
        import_pattern = r'import\s+([^;]+);'
        
        for match in re.finditer(import_pattern, content):
            imports.append(match.group(1).strip())
    
    return list(set(imports))

def extract_endpoints(content, language):
    """Extract API endpoints from file content."""
    endpoints = []
    
    if language == "python":
        # Look for Flask/Django/FastAPI endpoints
        endpoint_patterns = [
            r'@app\.route\s*\(\s*[\'"]([^\'"]+)[\'"]',
            r'@app\.\w+\s*\(\s*[\'"]([^\'"]+)[\'"]',
            r'path\s*\(\s*[\'"]([^\'"]+)[\'"]',
            r'url\s*\(\s*[\'"]([^\'"]+)[\'"]'
        ]
        
        for pattern in endpoint_patterns:
            for match in re.finditer(pattern, content):
                endpoints.append(match.group(1))
    
    elif language in ["javascript", "typescript"]:
        # Look for Express/Node.js endpoints
        endpoint_patterns = [
            r'app\.(get|post|put|delete|patch)\s*\(\s*[\'"]([^\'"]+)[\'"]',
            r'router\.(get|post|put|delete|patch)\s*\(\s*[\'"]([^\'"]+)[\'"]'
        ]
        
        for pattern in endpoint_patterns:
            for match in re.finditer(pattern, content):
                endpoints.append(match.group(2))
    
    elif language == "java":
        # Look for Spring/JAX-RS endpoints
        endpoint_patterns = [
            r'@RequestMapping\s*\(\s*[\'"]([^\'"]+)[\'"]',
            r'@GetMapping\s*\(\s*[\'"]([^\'"]+)[\'"]',
            r'@PostMapping\s*\(\s*[\'"]([^\'"]+)[\'"]',
            r'@PutMapping\s*\(\s*[\'"]([^\'"]+)[\'"]',
            r'@DeleteMapping\s*\(\s*[\'"]([^\'"]+)[\'"]',
            r'@Path\s*\(\s*[\'"]([^\'"]+)[\'"]'
        ]
        
        for pattern in endpoint_patterns:
            for match in re.finditer(pattern, content):
                endpoints.append(match.group(1))
    
    return list(set(endpoints))

def extract_critical_functions(content, language):
    """Extract security-critical functions from file content."""
    critical_funcs = []
    
    # Generic critical function patterns for all languages
    patterns = [
        r'(authenticate|login|authorize|password|credential|token|key|secret|encrypt|decrypt|hash|permission|access|admin|root)',
        r'(exec|eval|system|command|execute|spawn|injection|sanitize|escape|validate|filter)',
        r'(sql|query|database|insert|update|delete|select|where)',
        r'(request|response|header|cookie|session|csrf|xss|html|url|redirect|forward)',
        r'(file|directory|path|upload|download|stream|read|write|open|close)'
    ]
    
    for pattern in patterns:
        # Look for function definitions containing these keywords
        func_def_pattern = rf'function\s+\w*{pattern}\w*\s*\(' if language in ["javascript", "typescript"] else \
                           rf'def\s+\w*{pattern}\w*\s*\(' if language == "python" else \
                           rf'\w+\s+\w*{pattern}\w*\s*\([^)]*\)' if language == "java" else \
                           rf'\w+\s+\w*{pattern}\w*\s*\('
        
        for match in re.finditer(func_def_pattern, content, re.IGNORECASE):
            critical_funcs.append(match.group(0))
    
    return list(set(critical_funcs))

def identify_critical_files(openai, model, project_structure, project_path):
    """
    Use GPT to identify which files are most critical for security scanning.
    Returns a list of file paths.
    """
    logger.info("Using GPT to identify critical files for security analysis...")
    
    # First, extract files with security-relevant indicators
    files_with_indicators = []
    
    def extract_files(structure, prefix=""):
        for name, info in structure.items():
            path = os.path.join(prefix, name)
            
            if isinstance(info, dict) and "type" in info:
                # This is a file
                security_score = 0
                reasons = []
                
                # Check for imports that might indicate security concerns
                if "imports" in info:
                    security_imports = [
                        imp for imp in info["imports"] 
                        if any(sec in imp.lower() for sec in [
                            "sql", "auth", "crypt", "token", "password", "login", "security",
                            "exec", "eval", "command", "system", "request", "http", "express",
                            "file", "path", "stream", "upload", "download"
                        ])
                    ]
                    if security_imports:
                        security_score += len(security_imports) * 2
                        reasons.append(f"Imports: {', '.join(security_imports)}")
                
                # Check for API endpoints
                if "endpoints" in info:
                    security_score += len(info["endpoints"]) * 3
                    reasons.append(f"Has {len(info['endpoints'])} API endpoints")
                
                # Check for critical functions
                if "critical_functions" in info:
                    security_score += len(info["critical_functions"]) * 3
                    reasons.append(f"Has {len(info['critical_functions'])} security-critical functions")
                
                # Bonus for specific file names that often have security implications
                if any(sec in name.lower() for sec in [
                    "auth", "login", "security", "password", "user", "admin", "permission",
                    "token", "jwt", "session", "cookie", "crypt", "hash", "controller",
                    "route", "api", "request", "response", "upload", "download", "validator",
                    "sanitize", "filter", "sql", "database", "config", "env", "secret"
                ]):
                    security_score += 5
                    reasons.append(f"Security-relevant filename: {name}")
                
                if security_score > 0:
                    files_with_indicators.append({
                        "path": path,
                        "score": security_score,
                        "reasons": reasons
                    })
            elif isinstance(info, dict):
                # This is a directory
                extract_files(info, path)
    
    extract_files(project_structure)
    
    # Sort files by security score (higher score = higher priority)
    files_with_indicators.sort(key=lambda x: x["score"], reverse=True)
    
    # If we found enough files with security indicators, use those
    if len(files_with_indicators) >= 15:
        logger.info(f"Identified {len(files_with_indicators)} critical files based on security indicators")
        return [f["path"] for f in files_with_indicators[:30]]
    
    # Otherwise, use GPT for more sophisticated analysis
    # First, get a high-level understanding of the project
    project_summary = analyze_project_summary(openai, model, project_path, project_structure)
    
    # Use the project summary to help identify critical files
    prompt = f"""
    As a security expert, analyze this project structure to identify which files should be prioritized for security scanning.
    
    Project Summary:
    {project_summary}
    
    Project Structure:
    {json.dumps(project_structure, indent=2)}
    
    Already Identified Files With Security Indicators:
    {json.dumps([f["path"] for f in files_with_indicators], indent=2)}
    
    Identify files that:
    1. Handle user input or data from untrusted sources
    2. Perform authentication, authorization, or session management
    3. Connect to external services, APIs, or databases
    4. Process sensitive data (PII, financial, health data)
    5. Execute system commands or perform file operations
    6. Implement security-critical functionality
    7. Are entry points to the application (e.g., API endpoints, controllers)
    8. Files that seem to contain security-related keywords in their content or path
    
    Ignore test files, documentation, and configuration files unless they contain credentials.
    Limit your selection to no more than 20-30 most security-critical files.
    
    Return ONLY a JSON array of file paths (no explanation needed):
    Example: ["src/controllers/auth.js", "api/endpoints.py"]
    """
    
    try:
        response = openai.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a security expert identifying critical files for security scanning."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,
            max_tokens=2000
        )
        
        # Parse the JSON response
        critical_files = json.loads(response.choices[0].message.content)
        if not isinstance(critical_files, list):
            raise ValueError("Response is not a list")
        
        # Add any files with indicators that weren't included
        for file_info in files_with_indicators:
            if file_info["path"] not in critical_files:
                critical_files.append(file_info["path"])
        
        return critical_files
    except Exception as e:
        logger.error(f"Error using GPT to identify critical files: {str(e)}")
        
        # Fall back to automated selection
        if files_with_indicators:
            return [f["path"] for f in files_with_indicators[:30]]
        else:
            return fallback_critical_file_selection(project_structure)

def analyze_project_summary(openai, model, project_path, project_structure):
    """
    Use GPT to generate a high-level summary of the project.
    """
    # Check for common project metadata files
    metadata_files = ["README.md", "package.json", "pom.xml", "requirements.txt", 
                     "setup.py", "build.gradle", "Gemfile", "composer.json"]
    
    metadata_content = ""
    for file in metadata_files:
        file_path = os.path.join(project_path, file)
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                metadata_content += f"\nContent of {file}:\n{content[:2000]}\n"
            except Exception as e:
                logger.debug(f"Error reading {file_path}: {str(e)}")
    
    # Find project root files
    root_files = []
    for name, info in project_structure.items():
        if isinstance(info, dict) and "type" in info:
            root_files.append(name)
    
    prompt = f"""
    Analyze this project structure and metadata to create a high-level summary of the project.
    Focus on:
    1. The type of application (web, mobile, desktop, etc.)
    2. Programming languages and frameworks used
    3. Main functionality and purpose
    4. Security-sensitive components or features
    5. Application architecture (API endpoints, database usage, etc.)
    
    Project root files: {', '.join(root_files)}
    
    {metadata_content}
    
    Keep your summary concise (3-5 sentences) and focus on information relevant for security analysis.
    """
    
    try:
        response = openai.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a security expert analyzing a software project."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,
            max_tokens=500
        )
        
        return response.choices[0].message.content
    except Exception as e:
        logger.error(f"Error generating project summary: {str(e)}")
        return "No project summary available."

def fallback_critical_file_selection(structure, prefix=""):
    """Fallback method to identify critical files based on naming patterns."""
    logger.info("Using fallback method for critical file selection")
    
    # Keywords that might indicate security-sensitive files
    security_keywords = [
        'auth', 'login', 'user', 'password', 'cred', 'admin', 'access',
        'security', 'permission', 'token', 'jwt', 'oauth', 'session',
        'api', 'controller', 'endpoint', 'route', 'handler', 'middleware',
        'database', 'sql', 'query', 'db', 'store', 'crypto', 'encrypt',
        'secret', 'key', 'cert', 'config', 'setting', 'env', 'http', 'request',
        'response', 'server', 'client', 'auth', 'file', 'upload', 'download',
        'exec', 'shell', 'command', 'process', 'stream', 'socket', 'cookie'
    ]
    
    # Common main application files by language
    main_app_files = {
        'python': ['app.py', 'main.py', 'wsgi.py', 'asgi.py', 'application.py', 'server.py'],
        'javascript': ['app.js', 'index.js', 'server.js', 'main.js', 'app.jsx', 'index.jsx'],
        'java': ['Main.java', 'Application.java', 'App.java', 'Server.java'],
        'ruby': ['application.rb', 'app.rb', 'main.rb', 'server.rb'],
        'php': ['index.php', 'app.php', 'main.php'],
        'go': ['main.go', 'app.go', 'server.go'],
    }
    
    # Important folders to focus on
    important_folders = [
        'api', 'controllers', 'routes', 'handlers', 'services', 'middleware',
        'auth', 'security', 'users', 'admin', 'src/main', 'app'
    ]
    
    file_scores = []
    
    def score_file(name, info, path):
        if "type" not in info:
            return None
        
        score = 0
        lower_name = name.lower()
        
        # Score based on filename
        for keyword in security_keywords:
            if keyword in lower_name:
                score += 5
        
        # Score based on main application files
        file_ext = info.get("type", "")
        language = info.get("language", "unknown")
        
        if language in main_app_files and lower_name in [f.lower() for f in main_app_files.get(language, [])]:
            score += 20
        
        # Score based on path containing important folders
        for folder in important_folders:
            if folder.lower() in path.lower():
                score += 5
        
        return {
            "path": path,
            "score": score,
            "size": info.get("size", 0)
        }
    
    def extract_scored_files(structure, prefix=""):
        for name, info in structure.items():
            path = os.path.join(prefix, name)
            
            if isinstance(info, dict) and "type" in info:
                # This is a file
                file_score = score_file(name, info, path)
                if file_score:
                    file_scores.append(file_score)
            elif isinstance(info, dict):
                # This is a directory
                extract_scored_files(info, path)
    
    extract_scored_files(structure)
    
    # Sort files by score (higher score = higher priority)
    file_scores.sort(key=lambda x: x["score"], reverse=True)
    
    # Take top 30 files
    critical_files = [f["path"] for f in file_scores[:30]]
    
    return critical_files