
import os
import time
import json
import logging
import concurrent.futures
from datetime import datetime
from tqdm import tqdm

from .cache import ScanCache
from .file_manager import get_project_structure, identify_critical_files
from .utils import get_language_for_file, get_file_context, map_to_cwe
from .dataflow import perform_enhanced_dataflow_analysis
from .ast_parser import parse_code_to_ast

class GPTSASTScanner:
    def __init__(self, api_key, model="gpt-4", db_path=".scan_cache.db", concurrent_scans=3, confidence_threshold=0.7):
        """Initialize the scanner with OpenAI API key and configuration."""
        self.api_key = api_key
        self.model = model
        self.concurrent_scans = concurrent_scans
        self.confidence_threshold = confidence_threshold
        self.logger = logging.getLogger('gpt_sast.scanner')
        
        # Set up OpenAI API
        import openai
        openai.api_key = api_key
        self.openai = openai
        
        # Initialize cache if db_path is provided
        self.cache = ScanCache(db_path) if db_path else None
        
    def scan_project(self, project_path, ignore_patterns=None, max_file_size=100000, max_files=None, scan_all=False):
        """Main scanning function that orchestrates the process."""
        self.logger.info(f"Starting scan of project: {project_path}")
        
        # 1. Get project structure
        self.logger.info("Analyzing project structure...")
        project_structure = get_project_structure(
            project_path, ignore_patterns, max_file_size, max_files
        )
        
        # 2. Identify critical files
        if scan_all:
            self.logger.info("Scan all mode enabled - scanning all source code files")
            critical_files = self._get_all_source_files(project_structure, max_files)
        else:
            # Check cache first
            critical_files = None
            if self.cache:
                critical_files = self.cache.get_project_critical_files(project_path, project_structure)
            
            if critical_files is None:
                self.logger.info("Identifying critical files...")
                critical_files = identify_critical_files(self.openai, self.model, project_structure, project_path)
                
                # Save to cache
                if self.cache:
                    self.cache.save_project_critical_files(project_path, project_structure, critical_files)
            else:
                self.logger.info("Using cached critical files list")
        
        # 3. Perform global project-level analysis
        self.logger.info("Performing project-level analysis...")
        project_context = self._analyze_project_context(project_path, critical_files)
        
        # 4. First-pass analysis to understand patterns and dependencies
        self.logger.info("Performing initial project pattern analysis...")
        pattern_analysis = self._analyze_project_patterns(project_path, critical_files, project_context)
        
        # 5. Scan critical files with enhanced dataflow analysis
        self.logger.info(f"Scanning {len(critical_files)} critical files with dataflow analysis...")
        vulnerabilities = []
        
        # Use thread pool for concurrent scanning
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrent_scans) as executor:
            scan_tasks = {}
            for file_path in critical_files:
                full_path = os.path.join(project_path, file_path)
                if os.path.exists(full_path):
                    future = executor.submit(self._scan_file_with_enhanced_dataflow, 
                                            full_path, project_context, pattern_analysis, max_file_size)
                    scan_tasks[future] = file_path
            
            # Show progress with tqdm
            with tqdm(total=len(scan_tasks), desc="Scanning files") as pbar:
                for future in concurrent.futures.as_completed(scan_tasks):
                    file_path = scan_tasks[future]
                    try:
                        file_vulnerabilities = future.result()
                        if file_vulnerabilities:
                            vulnerabilities.extend(file_vulnerabilities)
                            self.logger.info(f"Found {len(file_vulnerabilities)} vulnerabilities in {file_path}")
                    except Exception as e:
                        self.logger.error(f"Error scanning {file_path}: {str(e)}")
                    pbar.update(1)
        
        # 6. Perform cross-file analysis to find multi-file vulnerabilities
        self.logger.info("Performing cross-file vulnerability analysis...")
        cross_file_vulnerabilities = self._analyze_cross_file_vulnerabilities(
            project_path, critical_files, vulnerabilities, project_context
        )
        if cross_file_vulnerabilities:
            vulnerabilities.extend(cross_file_vulnerabilities)
        
        # 7. Filter out false positives based on confidence
        filtered_vulnerabilities = [v for v in vulnerabilities if v.get("confidence", 0) >= self.confidence_threshold]
        self.logger.info(f"Filtered out {len(vulnerabilities) - len(filtered_vulnerabilities)} potential false positives")
        
        # 8. Extract unique vulnerability types
        vuln_types = set()
        for vuln in filtered_vulnerabilities:
            vuln_types.add(vuln.get("vulnerability_type", "Unknown"))
        
        # 9. Get security recommendations
        self.logger.info("Generating security recommendations...")
        recommendations = self._generate_security_recommendations(filtered_vulnerabilities, list(vuln_types))
        
        # 10. Generate risk score
        severity_weights = {
            "Critical": 10,
            "High": 7,
            "Medium": 4,
            "Low": 1
        }
        
        total_severity = sum(severity_weights.get(v.get("severity", "Low"), 1) for v in filtered_vulnerabilities)
        num_files_with_vulns = len(set(v.get("file", "") for v in filtered_vulnerabilities))
        risk_score = min(100, int((total_severity / max(1, len(critical_files))) * 25 + 
                               (num_files_with_vulns / max(1, len(critical_files))) * 75))
        
        # 11. Generate summary report
        summary = {
            "project": project_path,
            "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "files_scanned": len(critical_files),
            "vulnerabilities_found": len(filtered_vulnerabilities),
            "unique_vulnerability_types": len(vuln_types),
            "risk_score": risk_score,
            "severity_breakdown": {
                "Critical": sum(1 for v in filtered_vulnerabilities if v.get("severity") == "Critical"),
                "High": sum(1 for v in filtered_vulnerabilities if v.get("severity") == "High"),
                "Medium": sum(1 for v in filtered_vulnerabilities if v.get("severity") == "Medium"),
                "Low": sum(1 for v in filtered_vulnerabilities if v.get("severity") == "Low")
            },
            "critical_files": critical_files,
            "vulnerabilities": filtered_vulnerabilities,
            "recommendations": recommendations,
            "vulnerability_types": list(vuln_types)
        }
        
        self.logger.info(f"Scan completed. Found {len(filtered_vulnerabilities)} vulnerabilities. Risk score: {risk_score}/100")
        
        return summary
    
    def _get_all_source_files(self, structure, max_files=None):
        """Extract all source code files from the project structure."""
        source_files = []
        
        def extract_files(structure, prefix=""):
            for name, info in structure.items():
                path = os.path.join(prefix, name)
                
                if isinstance(info, dict) and "type" in info:
                    # This is a file with a recognized extension
                    source_files.append(path)
                elif isinstance(info, dict):
                    # This is a directory
                    extract_files(info, path)
        
        extract_files(structure)
        
        if max_files:
            return source_files[:max_files]
        return source_files
    
    def _analyze_project_context(self, project_path, critical_files):
        """Analyze project structure to identify frameworks, dependencies, etc."""
        self.logger.info("Analyzing project context...")
        
        # Look for common configuration files
        config_files = []
        for file in os.listdir(project_path):
            if file in ["package.json", "pom.xml", "build.gradle", "requirements.txt", 
                       "Gemfile", "composer.json", "Cargo.toml", ".gitignore"]:
                config_files.append(file)
        
        # Read framework information
        frameworks = {}
        dependencies = {}
        
        for file in config_files:
            file_path = os.path.join(project_path, file)
            if os.path.exists(file_path):
                with open(file_path, 'r', errors='ignore') as f:
                    content = f.read()
                    
                    if file == "package.json":
                        try:
                            data = json.loads(content)
                            dependencies.update(data.get("dependencies", {}))
                            dependencies.update(data.get("devDependencies", {}))
                            if "react" in dependencies:
                                frameworks["react"] = dependencies["react"]
                            if "angular" in dependencies:
                                frameworks["angular"] = dependencies["angular"]
                            if "vue" in dependencies:
                                frameworks["vue"] = dependencies["vue"]
                            if "express" in dependencies:
                                frameworks["express"] = dependencies["express"]
                        except json.JSONDecodeError:
                            pass
                    
                    elif file == "pom.xml" and "<artifactId>" in content:
                        if "spring-boot" in content:
                            frameworks["spring-boot"] = True
                        if "spring-security" in content:
                            frameworks["spring-security"] = True
                    
                    elif file == "requirements.txt":
                        if "django" in content:
                            frameworks["django"] = True
                        if "flask" in content:
                            frameworks["flask"] = True
        
        # Get entry points
        entry_points = []
        for file in critical_files:
            full_path = os.path.join(project_path, file)
            if os.path.exists(full_path):
                with open(full_path, 'r', errors='ignore') as f:
                    content = f.read()
                    if "main(" in content or "public static void main" in content:
                        entry_points.append(file)
                    if "app.listen" in content or "runserver" in content:
                        entry_points.append(file)
                    
        return {
            "frameworks": frameworks,
            "dependencies": dependencies,
            "config_files": config_files,
            "entry_points": entry_points
        }
    
    def _analyze_project_patterns(self, project_path, critical_files, project_context):
        """Analyze common patterns, custom functions, and potential vulnerability sources/sinks."""
        # This new first-pass analysis helps understand project-specific patterns
        self.logger.info("Analyzing project-specific code patterns...")
        
        # Start with basic patterns
        patterns = {
            "custom_functions": {},
            "data_transformations": [],
            "validation_functions": [],
            "wrapper_functions": [],
            "security_patterns": {
                "authentication": [],
                "authorization": [],
                "encryption": [],
                "sanitization": []
            }
        }
        
        # Sample critical files for pattern analysis (to avoid analyzing all files)
        sample_size = min(5, len(critical_files))
        sampled_files = critical_files[:sample_size]
        
        # Analyze each sampled file for patterns
        for file in sampled_files:
            full_path = os.path.join(project_path, file)
            if os.path.exists(full_path):
                try:
                    with open(full_path, 'r', errors='ignore') as f:
                        content = f.read()
                    
                    # Get language
                    language = get_language_for_file(full_path)
                    
                    # Ask GPT to identify patterns in this file
                    file_patterns = self._identify_file_patterns(full_path, content, language, project_context)
                    
                    # Merge file patterns into overall project patterns
                    if file_patterns:
                        # Merge custom functions
                        for func_name, func_info in file_patterns.get("custom_functions", {}).items():
                            patterns["custom_functions"][func_name] = func_info
                        
                        # Add data transformations
                        patterns["data_transformations"].extend(file_patterns.get("data_transformations", []))
                        
                        # Add validation functions
                        patterns["validation_functions"].extend(file_patterns.get("validation_functions", []))
                        
                        # Add wrapper functions
                        patterns["wrapper_functions"].extend(file_patterns.get("wrapper_functions", []))
                        
                        # Merge security patterns
                        for category, funcs in file_patterns.get("security_patterns", {}).items():
                            if category in patterns["security_patterns"]:
                                patterns["security_patterns"][category].extend(funcs)
                
                except Exception as e:
                    self.logger.error(f"Error analyzing patterns in {file}: {str(e)}")
        
        # Deduplicate lists
        for key in ["data_transformations", "validation_functions", "wrapper_functions"]:
            patterns[key] = list(set(patterns[key]))
        
        for category in patterns["security_patterns"]:
            patterns["security_patterns"][category] = list(set(patterns["security_patterns"][category]))
        
        return patterns
    
    def _identify_file_patterns(self, file_path, content, language, project_context):
        """Use GPT to identify code patterns in a file."""
        try:
            # Extract function definitions
            ast_data = parse_code_to_ast(file_path, content, language)
            
            # Prepare prompt for GPT
            prompt = f"""
            Analyze this {language} file to identify common patterns, custom functions, and potential security-related code.
            
            File: {file_path}
            
            Project Context:
            - Frameworks: {', '.join(project_context.get('frameworks', {}).keys())}
            - Dependencies: {', '.join(list(project_context.get('dependencies', {}).keys())[:10])}
            
            Code:
            ```{language}
            {content[:12000] if len(content) > 12000 else content}
            ```
            
            Please identify:
            1. Custom functions that perform data processing, transformation, or validation
            2. Functions that might be used for encoding/decoding or obfuscating data
            3. Validation or sanitization functions that might be incomplete or bypassed
            4. Wrapper functions that might hide security-sensitive operations
            5. Authentication, authorization, or security enforcement patterns
            
            Return your analysis as JSON in this format:
            {
                "custom_functions": {
                    "function_name": {
                        "purpose": "brief description of function purpose",
                        "potential_security_impact": "potential security relevance",
                        "parameters": ["param1", "param2"],
                        "called_by": ["parent_function1"],
                        "calls": ["child_function1", "child_function2"]
                    }
                },
                "data_transformations": ["function_name1", "function_name2"],
                "validation_functions": ["function_name1", "function_name2"],
                "wrapper_functions": ["function_name1", "function_name2"],
                "security_patterns": {
                    "authentication": ["function_name1", "function_name2"],
                    "authorization": ["function_name1", "function_name2"],
                    "encryption": ["function_name1", "function_name2"],
                    "sanitization": ["function_name1", "function_name2"]
                }
            }
            """
            
            # Get GPT response
            response = self.openai.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security expert analyzing code patterns for security vulnerabilities."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=3000
            )
            
            # Parse the JSON response
            try:
                result = json.loads(response.choices[0].message.content)
                return result
            except json.JSONDecodeError:
                # Try to extract JSON if response has text around it
                content = response.choices[0].message.content
                json_start = content.find('{')
                json_end = content.rfind('}') + 1
                
                if json_start >= 0 and json_end > json_start:
                    try:
                        result = json.loads(content[json_start:json_end])
                        return result
                    except:
                        pass
                
                self.logger.warning(f"Could not parse JSON response for pattern analysis of {file_path}")
                return {}
                
        except Exception as e:
            self.logger.error(f"Error identifying patterns in {file_path}: {str(e)}")
            return {}
    
    def _scan_file_with_enhanced_dataflow(self, file_path, project_context, pattern_analysis, max_file_size=100000):
        """Scan a file using enhanced dataflow analysis and GPT."""
        try:
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            self.logger.warning(f"Could not read file: {file_path} - {str(e)}")
            return []
        
        # Skip empty files or very large files
        if not content or len(content) > max_file_size:
            if len(content) > max_file_size:
                self.logger.info(f"File too large to scan: {file_path}")
            return []
        
        # Check if scan is cached
        if self.cache:
            cached_vulnerabilities = self.cache.get_file_vulnerabilities(file_path, content)
            if cached_vulnerabilities is not None:
                self.logger.info(f"Using cached scan results for {file_path}")
                return cached_vulnerabilities
        
        # Get language for the file
        language = get_language_for_file(file_path)
        
        # Parse code to AST
        ast_data = parse_code_to_ast(file_path, content, language)
        
        # Perform enhanced data flow analysis with pattern context
        dataflow_results = perform_enhanced_dataflow_analysis(
            ast_data, content, language, pattern_analysis
        )
        
        # Get surrounding context
        file_context = get_file_context(file_path, project_context)
        
        # Ask GPT to analyze with enhanced context
        try:
            vulnerabilities = self._analyze_with_gpt(
                file_path, content, language, dataflow_results, file_context, pattern_analysis
            )
            
            # Cache the results
            if self.cache:
                self.cache.save_file_vulnerabilities(file_path, content, vulnerabilities)
            
            return vulnerabilities
        except Exception as e:
            self.logger.error(f"Error scanning {file_path}: {str(e)}")
            return []
    
    def _analyze_with_gpt(self, file_path, content, language, dataflow_results, file_context, pattern_analysis):
        """Use GPT to analyze code and identify vulnerabilities with enhanced context."""
        # Truncate content if too large for the model context window
        max_content_length = 12000
        if len(content) > max_content_length:
            # Keep beginning and end of file, truncate middle
            half_len = max_content_length // 2
            content_for_gpt = content[:half_len] + "\n\n... [Content truncated due to length] ...\n\n" + content[-half_len:]
        else:
            content_for_gpt = content
        
        # Build a detailed prompt with data flow information
        dataflow_info = ""
        if dataflow_results:
            dataflow_info = "Data Flow Analysis Results:\n"
            
            # Add source-sink flows
            if dataflow_results.get("source_sink_flows"):
                dataflow_info += "Source-Sink Flows (potential vulnerabilities):\n"
                for i, flow in enumerate(dataflow_results.get("source_sink_flows", [])[:10]):
                    dataflow_info += f"{i+1}. {flow['source_type']} at line {flow['source_line']} flows to {flow['sink_type']} at line {flow['sink_line']}\n"
                    dataflow_info += f"   Source: {flow['source_code']}\n"
                    dataflow_info += f"   Flow Path: {' -> '.join(flow.get('flow_path', ['direct']))}\n"
                    dataflow_info += f"   Sink: {flow['sink_code']}\n"
                    dataflow_info += f"   Sanitized: {flow['sanitized']}\n\n"
            
            # Add taint propagation
            if dataflow_results.get("taint_propagation"):
                dataflow_info += "Taint Propagation:\n"
                for i, taint in enumerate(dataflow_results.get("taint_propagation", [])[:10]):
                    dataflow_info += f"{i+1}. Tainted variable '{taint['variable']}' at line {taint['line']} from {taint['source']}\n"
                    if 'transformations' in taint:
                        dataflow_info += f"   Transformations: {', '.join(taint['transformations'])}\n"
            
            # Add validation attempts
            if dataflow_results.get("validation_attempts"):
                dataflow_info += "\nValidation Attempts (potential bypasses):\n"
                for i, validation in enumerate(dataflow_results.get("validation_attempts", [])[:5]):
                    dataflow_info += f"{i+1}. Validation at line {validation['line']} for input from line {validation['input_line']}\n"
                    dataflow_info += f"   Validation code: {validation['validation_code']}\n"
                    dataflow_info += f"   Potential bypass: {validation['potential_bypass']}\n\n"
            
            # Add suspicious patterns
            if dataflow_results.get("suspicious_patterns"):
                dataflow_info += "\nSuspicious Patterns:\n"
                for i, pattern in enumerate(dataflow_results.get("suspicious_patterns", [])[:5]):
                    dataflow_info += f"{i+1}. {pattern['type']} at line {pattern['line']}: {pattern['description']}\n"
                    dataflow_info += f"   Code: {pattern['code']}\n\n"
        
        # Add context information with pattern analysis
        context_info = f"""
File Context:
- Framework: {', '.join(file_context.get('frameworks', []))}
- Dependencies: {', '.join(list(file_context.get('dependencies', {}).keys())[:10])}
- File purpose: {file_context.get('purpose', 'Unknown')}
- API endpoints: {', '.join(file_context.get('endpoints', []))}

Project-Specific Patterns:
- Custom security functions: {', '.join(pattern_analysis.get('security_patterns', {}).get('authentication', []) + 
                                     pattern_analysis.get('security_patterns', {}).get('authorization', []) + 
                                     pattern_analysis.get('security_patterns', {}).get('encryption', []) + 
                                     pattern_analysis.get('security_patterns', {}).get('sanitization', []))}
- Data transformation functions: {', '.join(pattern_analysis.get('data_transformations', []))}
- Validation functions: {', '.join(pattern_analysis.get('validation_functions', []))}
- Wrapper functions: {', '.join(pattern_analysis.get('wrapper_functions', []))}
"""
        
        # Determine file type for better analysis
        file_ext = os.path.splitext(file_path)[1].lower()
        file_type_context = ""
        if file_ext in ['.xml', '.pom', '.config', '.properties', '.yaml', '.yml']:
            file_type_context = "\nThis is a configuration file. Focus on security issues like hardcoded credentials, insecure settings, or vulnerable dependencies."
        elif file_ext in ['.html', '.htm', '.css']:
            file_type_context = "\nThis is a web markup/style file. Focus on client-side vulnerabilities like XSS, CSRF, or insecure resource loading."
        elif file_ext in ['.md', '.txt', '.rst']:
            file_type_context = "\nThis is a documentation file. Focus on potential sensitive information exposure or hardcoded credentials."
        
        # Build a detailed prompt for GPT
        prompt = f"""
Conduct a comprehensive security audit of this code with a focus on sophisticated vulnerabilities that might evade basic pattern matching.

File: {file_path}
Language: {language}
{file_type_context}

{context_info}

{dataflow_info}

Code:
```{language}
{content_for_gpt}
```

IMPORTANT INSTRUCTIONS FOR ENHANCED VULNERABILITY DETECTION:

1. Focus on sophisticated vulnerabilities that might evade basic SAST tools:
   - Multi-step vulnerabilities where data passes through several functions
   - Vulnerabilities hidden behind encoding/decoding or data transformations
   - Bypasses of validation functions that appear secure but aren't comprehensive
   - Second-order vulnerabilities where data is stored and used later
   - Logic flaws in validation that could be bypassed by specific inputs

2. Pay special attention to:
   - Custom data transformation functions that might inadequately protect sensitive operations
   - Validation functions that check for common attack patterns but miss specific techniques
   - Sanitization attempts that remove some dangerous patterns but not all
   - Complex data flow through multiple functions that culminate in vulnerable operations
   - Hidden backdoors or vulnerable debug functionality

3. For each vulnerability found:
   - Identify the exact line number(s) involved
   - Classify the vulnerability type specifically
   - Explain the full data flow that creates the vulnerability
   - Rate severity (Critical, High, Medium, Low)
   - Assign a confidence score (0.0-1.0) based on certainty
   - Map to CWE ID if applicable
   - Suggest specific remediation that addresses the root cause

4. For sophisticated vulnerabilities, explain:
   - How data flows between functions/transformations to create the vulnerability
   - Why validation or sanitization might be bypassed
   - What specific inputs could trigger the vulnerability

Return results in this exact JSON format:
[
  {{
    "line": line_number,
    "vulnerability_type": "specific vulnerability type",
    "description": "detailed description explaining why this is a vulnerability, including data flow",
    "severity": "Critical|High|Medium|Low",
    "confidence": confidence_score_between_0_and_1,
    "code_snippet": "relevant code snippet",
    "cwe_id": "CWE-XXX if applicable",
    "data_flow": ["step1", "step2", "step3"],
    "remediation": "specific code-based suggestion to fix the issue"
  }}
]

If no vulnerabilities are found, return an empty array: []
"""
        
        try:
            # Get GPT analysis
            response = self.openai.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security expert specialized in detecting sophisticated vulnerabilities that basic SAST tools miss."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.1,
                max_tokens=4000
            )
            
            # Get the response content
            response_content = response.choices[0].message.content.strip()
            
            # Try to parse the JSON response
            try:
                # Check if the response is empty or whitespace
                if not response_content:
                    self.logger.warning(f"Empty response from GPT for {file_path}. Treating as no vulnerabilities found.")
                    return []
                    
                # Check if the response looks like JSON (starts with [ or {)
                if response_content.startswith('[') or response_content.startswith('{'):
                    try:
                        vulnerabilities = json.loads(response_content)
                        
                        # Validate and enhance the structure if it's not an empty array
                        if vulnerabilities and isinstance(vulnerabilities, list):
                            # Check if each item has the required fields
                            for vuln in vulnerabilities:
                                if not isinstance(vuln, dict):
                                    self.logger.warning(f"Invalid vulnerability object in response for {file_path}: {vuln}")
                                    continue
                                    
                                # Ensure required fields are present, add defaults if missing
                                vuln["file"] = file_path
                                vuln.setdefault("line", 0)
                                vuln.setdefault("vulnerability_type", "Unknown")
                                vuln.setdefault("description", "No description provided")
                                vuln.setdefault("severity", "Medium")
                                vuln.setdefault("confidence", 0.5)
                                vuln.setdefault("code_snippet", "")
                                vuln.setdefault("cwe_id", "")
                                vuln.setdefault("remediation", "")
                                
                                # Add CWE ID if missing but vulnerability type is known
                                if not vuln["cwe_id"] and vuln["vulnerability_type"] != "Unknown":
                                    cwe_id = map_to_cwe(vuln["vulnerability_type"])
                                    if cwe_id:
                                        vuln["cwe_id"] = cwe_id
                        
                        return vulnerabilities if isinstance(vulnerabilities, list) else []
                        
                    except json.JSONDecodeError as e:
                        self.logger.error(f"Error parsing JSON from GPT response for {file_path}: {str(e)}")
                        self.logger.debug(f"Raw response: {response_content}")
                
                # Not valid JSON or doesn't start with JSON markers, try to extract JSON part
                import re
                
                # Look for array of vulnerabilities pattern
                json_match = re.search(r'(\[\s*\{.*\}\s*\])', response_content, re.DOTALL)
                if json_match:
                    try:
                        extracted_json = json_match.group(0)
                        vulnerabilities = json.loads(extracted_json)
                        
                        # Add file path to each vulnerability
                        if isinstance(vulnerabilities, list):
                            for vuln in vulnerabilities:
                                if isinstance(vuln, dict):
                                    vuln["file"] = file_path
                            
                            self.logger.info(f"Successfully extracted JSON from GPT response for {file_path}")
                            return vulnerabilities
                    except json.JSONDecodeError:
                        pass
                
                # Look for empty array pattern
                empty_array_match = re.search(r'\[\s*\]', response_content)
                if empty_array_match:
                    self.logger.info(f"No vulnerabilities found in {file_path}")
                    return []
                
                # Failed to find valid JSON, try to extract structured information
                self.logger.warning(f"GPT response for {file_path} is not in valid JSON format. Attempting to extract structured information.")
                
                # Look for vulnerability patterns in text format
                vuln_patterns = re.findall(r'(Vulnerability|Issue|Problem) \d+:.*?Line (\d+).*?(SQL Injection|XSS|Command Injection|Path Traversal|Insecure Deserialization|Weak Cryptography|Code Injection)', response_content, re.DOTALL)
                
                if vuln_patterns:
                    # Try to construct vulnerabilities from text patterns
                    text_vulnerabilities = []
                    for _, line, vuln_type in vuln_patterns:
                        text_vulnerabilities.append({
                            "file": file_path,
                            "line": int(line) if line.isdigit() else 0,
                            "vulnerability_type": vuln_type,
                            "description": "Extracted from non-JSON response",
                            "severity": "Medium",
                            "confidence": 0.5,
                            "code_snippet": "",
                            "cwe_id": map_to_cwe(vuln_type),
                            "remediation": "See detailed scanner logs for more information"
                        })
                    
                    if text_vulnerabilities:
                        self.logger.info(f"Extracted {len(text_vulnerabilities)} vulnerabilities from text response for {file_path}")
                        return text_vulnerabilities
                
                # Log the issue and return empty list
                self.logger.debug(f"Raw response: {response_content[:500]}...")  # Log first 500 chars 
                return []
                    
            except Exception as e:
                self.logger.error(f"Error processing GPT response for {file_path}: {str(e)}")
                self.logger.debug(f"Raw response: {response_content[:500]}...")
                return []
                
        except Exception as e:
            self.logger.error(f"Error getting GPT analysis for {file_path}: {str(e)}")
            return []
    
    def _analyze_cross_file_vulnerabilities(self, project_path, critical_files, vulnerabilities, project_context):
        """Analyze for vulnerabilities that span multiple files."""
        self.logger.info("Analyzing for cross-file vulnerabilities...")
        
        # Extract file contents
        file_contents = {}
        for file_path in critical_files:
            full_path = os.path.join(project_path, file_path)
            if os.path.exists(full_path):
                try:
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                        file_contents[file_path] = f.read()
                except Exception as e:
                    self.logger.warning(f"Could not read file for cross-file analysis: {file_path} - {str(e)}")
        
        # If not enough files, skip
        if len(file_contents) < 2:
            return []
        
        # Build a map of functions/classes and their locations
        code_entities = {}
        for file_path, content in file_contents.items():
            # Extract function and class definitions
            language = get_language_for_file(file_path)
            ast_data = parse_code_to_ast(file_path, content, language)
            
            # Add to entities map
            for entity in ast_data.get("functions", []):
                code_entities[entity["name"]] = {
                    "file": file_path,
                    "type": "function",
                    "line": entity.get("line", 0)
                }
            
            for entity in ast_data.get("classes", []):
                code_entities[entity["name"]] = {
                    "file": file_path,
                    "type": "class",
                    "line": entity.get("line", 0)
                }
        
        # Find function/method calls across files
        cross_file_calls = []
        for file_path, content in file_contents.items():
            language = get_language_for_file(file_path)
            lines = content.split('\n')
            
            # Look for calls to functions defined in other files
            for entity_name, entity_info in code_entities.items():
                if entity_info["file"] != file_path:  # Only look for cross-file calls
                    # Simple pattern matching for function calls
                    pattern = rf'{entity_name}\s*\('
                    import re
                    for i, line in enumerate(lines):
                        if re.search(pattern, line):
                            cross_file_calls.append({
                                "caller_file": file_path,
                                "caller_line": i + 1,
                                "called_entity": entity_name,
                                "called_file": entity_info["file"],
                                "called_line": entity_info["line"]
                            })
        
        # Check for cross-file vulnerabilities
        if not cross_file_calls:
            return []
        
        # Analyze cross-file vulnerabilities with GPT
        try:
            cross_file_vulns = self._analyze_cross_file_with_gpt(
                cross_file_calls, vulnerabilities, file_contents, project_context
            )
            return cross_file_vulns
        except Exception as e:
            self.logger.error(f"Error analyzing cross-file vulnerabilities: {str(e)}")
            return []
    
    def _analyze_cross_file_with_gpt(self, cross_file_calls, vulnerabilities, file_contents, project_context):
        """Use GPT to analyze cross-file vulnerability potential."""
        # Limit the analysis to a manageable number of calls
        sample_calls = cross_file_calls[:5]  # Take top 5 cross-file calls
        
        # Prepare the cross-file context for GPT
        cross_file_context = "Cross-File Function Calls:\n"
        for i, call in enumerate(sample_calls):
            cross_file_context += f"{i+1}. File '{call['caller_file']}' line {call['caller_line']} calls '{call['called_entity']}' from file '{call['called_file']}' line {call['called_line']}\n"
            
            # Add code snippets
            caller_content = file_contents.get(call['caller_file'], '')
            called_content = file_contents.get(call['called_file'], '')
            
            caller_lines = caller_content.split('\n')
            called_lines = called_content.split('\n')
            
            # Get caller context (3 lines before and after)
            caller_start = max(0, call['caller_line'] - 4)
            caller_end = min(len(caller_lines) - 1, call['caller_line'] + 2)
            caller_snippet = '\n'.join(caller_lines[caller_start:caller_end+1])
            
            # Get called context (function definition)
            called_start = max(0, call['called_line'] - 2)
            called_end = min(len(called_lines) - 1, call['called_line'] + 5)
            called_snippet = '\n'.join(called_lines[called_start:called_end+1])
            
            cross_file_context += f"   Caller code:\n```\n{caller_snippet}\n```\n"
            cross_file_context += f"   Called code:\n```\n{called_snippet}\n```\n\n"
        
        # Prepare existing vulnerabilities context
        vuln_context = "Previously Identified Vulnerabilities:\n"
        for i, vuln in enumerate(vulnerabilities[:5]):  # Limit to top 5
            vuln_context += f"{i+1}. {vuln.get('vulnerability_type')} in {vuln.get('file')} line {vuln.get('line')}\n"
            vuln_context += f"   Description: {vuln.get('description')}\n\n"
        
        # Prepare the prompt
        prompt = f"""
Analyze these cross-file function calls to identify vulnerabilities that span multiple files.
Look for:
1. Insecure data passing between files
2. Incomplete validation chains where validation in one file can be bypassed
3. Unsafe usage of functions from one file in another
4. Broken authentication or authorization flows spanning multiple files

{cross_file_context}

{vuln_context}

For each cross-file vulnerability found, provide:
1. The files and functions involved
2. The vulnerability type
3. How the vulnerability manifests across files
4. The severity and confidence level
5. Recommendations for fixing

Return the results in JSON format:
[
  {{
    "files_involved": ["file1.py", "file2.py"],
    "functions_involved": ["func1", "func2"],
    "vulnerability_type": "specific vulnerability type",
    "description": "detailed description of the cross-file vulnerability",
    "severity": "Critical|High|Medium|Low",
    "confidence": confidence_score_between_0_and_1,
    "cwe_id": "CWE-XXX if applicable",
    "remediation": "specific suggestion to fix the cross-file issue"
  }}
]

If no cross-file vulnerabilities are found, return an empty array: []
"""
        
        # Get GPT analysis
        response = self.openai.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": "You are a security expert specialized in detecting cross-file vulnerabilities in application code."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,
            max_tokens=3000
        )
        
        # Parse the response
        try:
            cross_file_vulns = json.loads(response.choices[0].message.content)
            
            # Format and enhance the vulnerabilities
            for vuln in cross_file_vulns:
                # Generate a code snippet combining both files
                snippet = f"Cross-file vulnerability between files:\n"
                for file in vuln.get("files_involved", []):
                    snippet += f"- {file}\n"
                
                # Add a common format to match single-file vulnerabilities
                vuln["code_snippet"] = snippet
                
                # Set line number to 0 as it spans files
                vuln["line"] = 0
                
                # Set file to the primary file involved
                if vuln.get("files_involved"):
                    vuln["file"] = vuln["files_involved"][0]
                
                # Add CWE ID if missing but vulnerability type is known
                if not vuln.get("cwe_id") and vuln.get("vulnerability_type"):
                    cwe_id = map_to_cwe(vuln["vulnerability_type"])
                    if cwe_id:
                        vuln["cwe_id"] = cwe_id
            
            return cross_file_vulns
            
        except json.JSONDecodeError:
            self.logger.warning("Could not parse cross-file vulnerability response as JSON")
            return []
        except Exception as e:
            self.logger.error(f"Error processing cross-file vulnerability analysis: {str(e)}")
            return []
    
    def _generate_security_recommendations(self, vulnerabilities, vulnerability_types):
        """Generate comprehensive security recommendations based on findings."""
        if not vulnerabilities:
            return []
        
        # Group vulnerabilities by type
        vuln_by_type = {}
        for vuln_type in vulnerability_types:
            type_vulns = [v for v in vulnerabilities if v.get("vulnerability_type") == vuln_type]
            if type_vulns:
                vuln_by_type[vuln_type] = type_vulns
        
        # Build specific examples for each vulnerability type
        type_examples = {}
        for vuln_type, vulns in vuln_by_type.items():
            # Take up to 3 examples per type
            examples = []
            for v in vulns[:3]:
                examples.append({
                    "file": v.get("file", ""),
                    "line": v.get("line", 0),
                    "code_snippet": v.get("code_snippet", ""),
                    "description": v.get("description", ""),
                    "confidence": v.get("confidence", 0.0),
                    "data_flow": v.get("data_flow", [])
                })
            type_examples[vuln_type] = examples
        
        prompt = f"""
As a security expert, provide detailed remediation recommendations for these vulnerability types found in the codebase:

{json.dumps(list(vulnerability_types), indent=2)}

Here are specific examples of each vulnerability type:

{json.dumps(type_examples, indent=2)}

For each vulnerability type, provide:
1. A detailed explanation of the security risk and its potential impact
2. Specific code patterns to avoid and patterns to implement instead
3. Best practices for preventing this type of vulnerability
4. Links to relevant security standards or guidelines (OWASP, CWE, etc.)
5. If framework-specific mitigations are available, include them
6. Root cause analysis explaining why this vulnerability tends to occur

Return the recommendations as a JSON array:
[
  {{
    "vulnerability_type": "type",
    "risk_explanation": "detailed explanation of the security risk and impact",
    "vulnerable_code_patterns": "patterns to avoid",
    "secure_code_examples": "secure code patterns to use instead",
    "best_practices": "best practices to prevent this vulnerability",
    "security_references": ["OWASP link", "CWE link", etc.],
    "root_causes": "why this vulnerability commonly occurs",
    "affected_files": ["file1", "file2", ...]
  }}
]
"""
        
        try:
            response = self.openai.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security expert providing detailed remediation recommendations."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=4000
            )
            
            # Parse the JSON response
            try:
                recommendations = json.loads(response.choices[0].message.content)
                
                # Add affected files to each recommendation
                for rec in recommendations:
                    vuln_type = rec.get("vulnerability_type", "")
                    affected_files = list(set([v.get("file", "") for v in vulnerabilities 
                                            if v.get("vulnerability_type") == vuln_type]))
                    rec["affected_files"] = affected_files
                
                return recommendations
            except json.JSONDecodeError as e:
                self.logger.error(f"Error parsing recommendations: {str(e)}")
                self.logger.debug(f"Raw response: {response.choices[0].message.content}")
                return []
        except Exception as e:
            self.logger.error(f"Error getting recommendations: {str(e)}")
            return []