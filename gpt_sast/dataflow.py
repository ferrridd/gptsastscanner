import logging
import re
from .sources_sinks import get_sources, get_sinks, get_sanitizers

logger = logging.getLogger('gpt_sast.dataflow')

def perform_enhanced_dataflow_analysis(ast_data, content, language, pattern_analysis=None):
    """
    Perform enhanced data flow analysis to track how user input (sources) 
    flows through the application to sensitive operations (sinks).
    
    Includes sophisticated tracking of data transformations and validation attempts.
    
    Args:
        ast_data: Abstract Syntax Tree data
        content: Source code content
        language: Programming language
        pattern_analysis: Project-specific patterns identified in the codebase
        
    Returns:
        Data flow vulnerabilities with detailed flow paths.
    """
    if not ast_data:
        logger.warning("AST data not available for dataflow analysis")
        return {}
    
    # Get language-specific sources, sinks and sanitizers
    sources = get_sources(language)
    sinks = get_sinks(language)
    sanitizers = get_sanitizers(language)
    
    # Enhance with project-specific patterns if available
    if pattern_analysis:
        # Add custom data transformation functions
        data_transforms = pattern_analysis.get('data_transformations', [])
        
        # Add custom validation functions
        validation_funcs = pattern_analysis.get('validation_functions', [])
        
        # Add security functions
        security_patterns = pattern_analysis.get('security_patterns', {})
        security_funcs = []
        for category, funcs in security_patterns.items():
            security_funcs.extend(funcs)
        
        # Add custom functions that might be relevant
        custom_functions = {}
        for name, info in pattern_analysis.get('custom_functions', {}).items():
            impact = info.get('potential_security_impact', '').lower()
            if any(keyword in impact for keyword in ['validation', 'sanitize', 'secure', 'transform', 'encode']):
                if 'sanitize' in impact or 'validate' in impact:
                    sanitizers.setdefault('custom_sanitization', []).append(name)
                if 'transform' in impact or 'encode' in impact:
                    custom_functions[name] = info
    
    # Extract variables, function calls, and their assignments from AST
    variables = extract_variables_enhanced(ast_data, content, language)
    
    # Identify sources in the code
    identified_sources = identify_sources_enhanced(ast_data, content, sources, pattern_analysis)
    
    # Identify sinks in the code
    identified_sinks = identify_sinks_enhanced(ast_data, content, sinks, pattern_analysis)
    
    # Identify sanitizations in the code
    identified_sanitizers = identify_sanitizers_enhanced(ast_data, content, sanitizers, pattern_analysis)
    
    # Track function calls
    function_calls = track_function_calls(ast_data, content, language)
    
    # Identify validation attempts that might be bypassed
    validation_attempts = identify_validation_attempts(ast_data, content, language, pattern_analysis)
    
    # Identify suspicious patterns
    suspicious_patterns = identify_suspicious_patterns(ast_data, content, language, pattern_analysis)
    
    # Build a call graph to track data flow between functions
    call_graph = build_call_graph(ast_data, function_calls, content, language)
    
    # Perform taint tracking with enhanced context
    tainted_variables = perform_taint_tracking_enhanced(
        identified_sources, variables, content, function_calls, call_graph, pattern_analysis
    )
    
    # Identify flows from sources to sinks with detailed paths
    source_sink_flows = identify_source_sink_flows_enhanced(
        identified_sources, identified_sinks, tainted_variables, 
        identified_sanitizers, function_calls, call_graph, validation_attempts
    )
    
    return {
        "source_sink_flows": source_sink_flows,
        "taint_propagation": tainted_variables,
        "identified_sources": identified_sources,
        "identified_sinks": identified_sinks,
        "identified_sanitizers": identified_sanitizers,
        "validation_attempts": validation_attempts,
        "suspicious_patterns": suspicious_patterns,
        "function_calls": function_calls,
        "call_graph": call_graph
    }

def extract_variables_enhanced(ast_data, content, language):
    """
    Extract variable definitions and assignments from AST with enhanced tracking.
    Tracks variable types, assignments and usages in function calls.
    
    Returns:
        list: Variables with their assignments, scopes, and usages.
    """
    variables = []
    
    if language == "python":
        variables = extract_python_variables_enhanced(ast_data, content)
    elif language in ["javascript", "typescript"]:
        variables = extract_js_variables_enhanced(ast_data, content)
    elif language == "java":
        variables = extract_java_variables_enhanced(ast_data, content)
    else:
        # Fallback to basic variable extraction
        variables = extract_basic_variables_enhanced(ast_data, content)
    
    # Second pass - resolve variable references and build usage chains
    for var in variables:
        var["references"] = []
        var["assignments"] = []
        
        # Look for references to this variable in other variables' initializers
        for other_var in variables:
            if var["name"] in other_var.get("initializer", ""):
                var["references"].append({
                    "line": other_var["line"],
                    "context": other_var["initializer"],
                    "var_name": other_var["name"]
                })
            
            # Look for this variable in assignments
            for assignment in other_var.get("later_assignments", []):
                if var["name"] in assignment.get("value", ""):
                    var["references"].append({
                        "line": assignment["line"],
                        "context": assignment["value"],
                        "var_name": other_var["name"]
                    })
            
        # Look for assignments to this variable
        for other_var in variables:
            for assignment in other_var.get("later_assignments", []):
                if assignment.get("var_name") == var["name"]:
                    var["assignments"].append({
                        "line": assignment["line"],
                        "value": assignment["value"]
                    })
    
    return variables

def extract_python_variables_enhanced(ast_data, content):
    """
    Extract variable definitions and assignments in Python code.
    Enhanced to track variable types and multiple assignments.
    """
    variables = []
    
    # Process nodes to find variable assignments
    for node in ast_data.get("nodes", []):
        if node.get("type") == "Assign":
            line = get_line_number(node, content)
            
            # Handle assignments like "x = 5" or "x, y = 1, 2"
            for target in node.get("targets", []):
                if target.get("type") == "Name":
                    name = target.get("id", "")
                    if name:
                        code_snippet = extract_code_snippet(content, line)
                        
                        # Try to extract the value being assigned
                        value = ""
                        equals_pos = code_snippet.find('=')
                        if equals_pos >= 0:
                            value = code_snippet[equals_pos + 1:].strip()
                        
                        # Find existing variable or create new one
                        existing_var = next((v for v in variables if v["name"] == name), None)
                        
                        if existing_var:
                            # Add this as a later assignment
                            existing_var.setdefault("later_assignments", []).append({
                                "line": line,
                                "value": value,
                                "var_name": name
                            })
                        else:
                            # Create new variable entry
                            variables.append({
                                "name": name,
                                "line": line,
                                "initializer": code_snippet,
                                "assigned_value": value,
                                "used_in": [],
                                "tainted": False,
                                "taint_source": None,
                                "later_assignments": []
                            })
        
        elif node.get("type") == "AugAssign":  # For +=, -=, etc.
            line = get_line_number(node, content)
            target = node.get("target", {})
            if target.get("type") == "Name":
                name = target.get("id", "")
                if name:
                    code_snippet = extract_code_snippet(content, line)
                    
                    # Try to extract the value being assigned
                    value = ""
                    op_pos = code_snippet.find('+=') or code_snippet.find('-=') or code_snippet.find('*=') or code_snippet.find('/=')
                    if op_pos >= 0:
                        value = code_snippet[op_pos + 2:].strip()
                    
                    # Find existing variable or create new one
                    existing_var = next((v for v in variables if v["name"] == name), None)
                    
                    if existing_var:
                        # Add this as a later assignment
                        existing_var.setdefault("later_assignments", []).append({
                            "line": line,
                            "value": value,
                            "var_name": name,
                            "augmented": True
                        })
                    else:
                        # Shouldn't happen as variables should be defined before augmented
                        # But add it just in case
                        variables.append({
                            "name": name,
                            "line": line,
                            "initializer": code_snippet,
                            "assigned_value": value,
                            "used_in": [],
                            "tainted": False,
                            "taint_source": None,
                            "later_assignments": []
                        })
    
    # Second pass to find variable usages
    for node in ast_data.get("nodes", []):
        if node.get("type") == "Name":
            name = node.get("id", "")
            line = get_line_number(node, content)
            
            # Find the variable
            for var in variables:
                if var["name"] == name:
                    usage_context = extract_code_snippet(content, line)
                    var.setdefault("usages", []).append({
                        "line": line,
                        "context": usage_context
                    })
    
    return variables

def extract_js_variables_enhanced(ast_data, content):
    """
    Extract variable definitions and assignments in JavaScript/TypeScript code.
    Enhanced to track scope and multiple assignments.
    """
    variables = []
    
    # Process nodes to find variable declarations and assignments
    for node in ast_data.get("nodes", []):
        if node.get("type") in ["VariableDeclaration", "VariableDeclarator"]:
            line = get_line_number(node, content)
            
            # Handle declarations like "let x = 5"
            if "declarations" in node:
                for decl in node.get("declarations", []):
                    name = decl.get("id", {}).get("name", "")
                    if name:
                        code_snippet = extract_code_snippet(content, line)
                        
                        # Try to extract the value being assigned
                        value = ""
                        equals_pos = code_snippet.find('=')
                        if equals_pos >= 0:
                            value = code_snippet[equals_pos + 1:].strip()
                            if value.endswith(';'):
                                value = value[:-1]
                        
                        variables.append({
                            "name": name,
                            "line": line,
                            "initializer": code_snippet,
                            "assigned_value": value,
                            "scope": node.get("kind", "var"),  # var, let, const
                            "used_in": [],
                            "tainted": False,
                            "taint_source": None,
                            "later_assignments": []
                        })
            
            # Handle individual declarators
            elif "id" in node:
                name = node.get("id", {}).get("name", "")
                if name:
                    code_snippet = extract_code_snippet(content, line)
                    
                    # Try to extract the value being assigned
                    value = ""
                    equals_pos = code_snippet.find('=')
                    if equals_pos >= 0:
                        value = code_snippet[equals_pos + 1:].strip()
                        if value.endswith(';'):
                            value = value[:-1]
                    
                    variables.append({
                        "name": name,
                        "line": line,
                        "initializer": code_snippet,
                        "assigned_value": value,
                        "scope": node.get("kind", "var"),  # var, let, const
                        "used_in": [],
                        "tainted": False,
                        "taint_source": None,
                        "later_assignments": []
                    })
        
        elif node.get("type") == "AssignmentExpression":
            line = get_line_number(node, content)
            left = node.get("left", {})
            
            # Handle both simple assignments and property assignments
            if left.get("type") == "Identifier":
                name = left.get("name", "")
            elif left.get("type") == "MemberExpression":
                name = left.get("object", {}).get("name", "") + "." + left.get("property", {}).get("name", "")
            else:
                name = ""
                
            if name:
                code_snippet = extract_code_snippet(content, line)
                
                # Try to extract the value being assigned
                value = ""
                equals_pos = code_snippet.find('=')
                if equals_pos >= 0:
                    value = code_snippet[equals_pos + 1:].strip()
                    if value.endswith(';'):
                        value = value[:-1]
                
                # Check if this is a later assignment to an existing variable
                existing_var = next((v for v in variables if v["name"] == name), None)
                
                if existing_var:
                    # Add this as a later assignment
                    existing_var.setdefault("later_assignments", []).append({
                        "line": line,
                        "value": value,
                        "var_name": name
                    })
                else:
                    # Create a new variable entry if it doesn't exist
                    variables.append({
                        "name": name,
                        "line": line,
                        "initializer": code_snippet,
                        "assigned_value": value,
                        "scope": "var",  # Default scope for assignments
                        "used_in": [],
                        "tainted": False,
                        "taint_source": None,
                        "later_assignments": []
                    })
    
    return variables

def extract_java_variables_enhanced(ast_data, content):
    """
    Extract variable definitions and assignments in Java code.
    Enhanced to track types and multiple assignments.
    """
    variables = []
    
    # Process nodes to find variable declarations and assignments
    for node in ast_data.get("nodes", []):
        if node.get("type") == "VariableDeclaration":
            line = get_line_number(node, content)
            name = node.get("name", "")
            var_type = node.get("variable_type", "")
            initializer = node.get("initializer", "")
            
            if name:
                code_snippet = extract_code_snippet(content, line)
                
                variables.append({
                    "name": name,
                    "line": line,
                    "initializer": code_snippet,
                    "assigned_value": initializer,
                    "var_type": var_type,
                    "used_in": [],
                    "tainted": False,
                    "taint_source": None,
                    "later_assignments": []
                })
        
        elif node.get("type") == "Assignment":
            line = get_line_number(node, content)
            left = node.get("left", {}).get("name", "")
            right = node.get("right", {})
            
            if left:
                code_snippet = extract_code_snippet(content, line)
                
                # Try to extract the value being assigned
                value = ""
                equals_pos = code_snippet.find('=')
                if equals_pos >= 0:
                    value = code_snippet[equals_pos + 1:].strip()
                    if value.endswith(';'):
                        value = value[:-1]
                
                # Check if this is a later assignment to an existing variable
                existing_var = next((v for v in variables if v["name"] == left), None)
                
                if existing_var:
                    # Add this as a later assignment
                    existing_var.setdefault("later_assignments", []).append({
                        "line": line,
                        "value": value,
                        "var_name": left
                    })
                else:
                    # Create a new variable entry if it doesn't exist
                    variables.append({
                        "name": left,
                        "line": line,
                        "initializer": code_snippet,
                        "assigned_value": value,
                        "var_type": "unknown",  # Type not specified in assignment
                        "used_in": [],
                        "tainted": False,
                        "taint_source": None,
                        "later_assignments": []
                    })
    
    return variables

def extract_basic_variables_enhanced(ast_data, content):
    """
    Basic fallback variable extraction using pattern matching.
    Enhanced to track multiple assignments.
    """
    variables = []
    lines = content.split('\n')
    
    # Simple regex-based extraction for demonstrations
    import re
    
    # Variables to track seen variables
    seen_vars = set()
    
    # Find variable assignments in lines
    for i, line in enumerate(lines):
        line_num = i + 1
        # Look for variable = value patterns
        matches = re.finditer(r'(\w+)\s*=\s*([^;]+)', line)
        for match in matches:
            name = match.group(1)
            initializer = match.group(2).strip()
            
            # Check if this is a new variable or later assignment
            if name in seen_vars:
                # Find the existing variable and add a later assignment
                for var in variables:
                    if var["name"] == name:
                        var.setdefault("later_assignments", []).append({
                            "line": line_num,
                            "value": initializer,
                            "var_name": name
                        })
                        break
            else:
                # New variable
                seen_vars.add(name)
                variables.append({
                    "name": name,
                    "line": line_num,
                    "initializer": line.strip(),
                    "assigned_value": initializer,
                    "used_in": [],
                    "tainted": False,
                    "taint_source": None,
                    "later_assignments": []
                })
    
    # Second pass to find variable usages
    for i, line in enumerate(lines):
        line_num = i + 1
        for var in variables:
            name = var["name"]
            # Look for variable usages that aren't assignments
            if name in line and f"{name} =" not in line and f"{name}=" not in line:
                usage_context = line.strip()
                var.setdefault("usages", []).append({
                    "line": line_num,
                    "context": usage_context
                })
    
    return variables

def identify_sources_enhanced(ast_data, content, sources, pattern_analysis=None):
    """
    Identify sources of user input in the code that could introduce tainted data.
    Enhanced to detect custom source patterns and multi-step sources.
    """
    identified_sources = []
    lines = content.split('\n')
    
    # Add project-specific source patterns if available
    if pattern_analysis and "custom_functions" in pattern_analysis:
        for name, info in pattern_analysis.get("custom_functions", {}).items():
            impact = info.get("potential_security_impact", "").lower()
            if "input" in impact or "user data" in impact or "request" in impact:
                sources.setdefault("custom_input", []).append(name)
    
    # Look for sources in the code using pattern matching
    for i, line in enumerate(lines):
        line_num = i + 1
        for source_type, patterns in sources.items():
            for pattern in patterns:
                if pattern in line:
                    source_context = get_context(content, line_num, 2)
                    identified_sources.append({
                        "line": line_num,
                        "source_type": source_type,
                        "source_code": line.strip(),
                        "source_pattern": pattern,
                        "context": source_context
                    })
    
    # Detect potential indirect sources (variables assigned from sources)
    for source in list(identified_sources):  # Use a copy to avoid modifying during iteration
        line_content = source["source_code"]
        
        # Try to identify if a variable is being assigned from this source
        assignment_match = re.search(r'(\w+)\s*=\s*.*' + re.escape(source["source_pattern"]), line_content)
        if assignment_match:
            var_name = assignment_match.group(1)
            
            # Look for uses of this variable that might be indirect sources
            for i, line in enumerate(lines):
                line_num = i + 1
                if var_name in line and line_num != source["line"]:
                    # Check if this looks like an assignment
                    assignment_to_new_var = re.search(r'(\w+)\s*=\s*.*' + re.escape(var_name), line)
                    if assignment_to_new_var:
                        new_var = assignment_to_new_var.group(1)
                        
                        # Add this as an indirect source
                        identified_sources.append({
                            "line": line_num,
                            "source_type": f"indirect_{source['source_type']}",
                            "source_code": line.strip(),
                            "source_pattern": var_name,
                            "parent_source": source,
                            "derived_variable": new_var
                        })
    
    return identified_sources

def identify_sinks_enhanced(ast_data, content, sinks, pattern_analysis=None):
    """
    Identify sinks in the code - places where tainted data could cause vulnerabilities.
    Enhanced to detect custom sink patterns and multi-step sinks.
    """
    identified_sinks = []
    lines = content.split('\n')
    
    # Add project-specific sink patterns if available
    if pattern_analysis and "custom_functions" in pattern_analysis:
        for name, info in pattern_analysis.get("custom_functions", {}).items():
            impact = info.get("potential_security_impact", "").lower()
            if any(word in impact for word in ["execute", "query", "sensitive", "critical"]):
                if "sql" in impact or "database" in impact:
                    sinks.setdefault("custom_sql", []).append(name)
                elif "command" in impact or "exec" in impact:
                    sinks.setdefault("custom_command", []).append(name)
                elif "output" in impact or "render" in impact:
                    sinks.setdefault("custom_output", []).append(name)
    
    # Look for sinks in the code using pattern matching
    for i, line in enumerate(lines):
        line_num = i + 1
        for sink_type, patterns in sinks.items():
            for pattern in patterns:
                if pattern in line:
                    sink_context = get_context(content, line_num, 2)
                    identified_sinks.append({
                        "line": line_num,
                        "sink_type": sink_type,
                        "sink_code": line.strip(),
                        "sink_pattern": pattern,
                        "context": sink_context
                    })
    
    # Look for wrapper functions that might hide sinks
    if pattern_analysis and "wrapper_functions" in pattern_analysis:
        for wrapper in pattern_analysis["wrapper_functions"]:
            # Look for uses of wrapper functions that might wrap sinks
            for i, line in enumerate(lines):
                if wrapper in line:
                    line_num = i + 1
                    wrapper_context = get_context(content, line_num, 3)
                    
                    # Try to determine if this wrapper involves a known sink
                    for sink_type, patterns in sinks.items():
                        for pattern in patterns:
                            for ctx_line in wrapper_context.split('\n'):
                                if pattern in ctx_line:
                                    identified_sinks.append({
                                        "line": line_num,
                                        "sink_type": f"wrapper_{sink_type}",
                                        "sink_code": line.strip(),
                                        "sink_pattern": wrapper,
                                        "wrapped_sink": pattern,
                                        "context": wrapper_context
                                    })
    
    return identified_sinks

def identify_sanitizers_enhanced(ast_data, content, sanitizers, pattern_analysis=None):
    """
    Identify sanitization functions in the code.
    Enhanced to detect custom sanitizers and multi-step sanitization.
    """
    identified_sanitizers = []
    lines = content.split('\n')
    
    # Add project-specific sanitizer patterns if available
    if pattern_analysis:
        # Add validation functions from pattern analysis
        validation_funcs = pattern_analysis.get("validation_functions", [])
        if validation_funcs:
            sanitizers.setdefault("custom_validation", []).extend(validation_funcs)
        
        # Add sanitization functions from security patterns
        security_sanitizers = pattern_analysis.get("security_patterns", {}).get("sanitization", [])
        if security_sanitizers:
            sanitizers.setdefault("custom_sanitization", []).extend(security_sanitizers)
    
    # Look for sanitization in the code using pattern matching
    for i, line in enumerate(lines):
        line_num = i + 1
        for sanitizer_type, patterns in sanitizers.items():
            for pattern in patterns:
                if pattern in line:
                    # Get more context to understand what's being sanitized
                    sanitizer_context = get_context(content, line_num, 2)
                    
                    # Try to determine what variable is being sanitized
                    sanitized_var = None
                    var_match = re.search(r'(\w+)\s*=\s*.*' + re.escape(pattern), line)
                    if var_match:
                        sanitized_var = var_match.group(1)
                    else:
                        # Try to find a variable in the function call
                        args_match = re.search(pattern + r'\s*\(([^)]+)\)', line)
                        if args_match:
                            args = args_match.group(1).split(',')
                            if args:
                                # Simply take the first argument as the sanitized variable
                                sanitized_var = args[0].strip()
                    
                    identified_sanitizers.append({
                        "line": line_num,
                        "sanitizer_type": sanitizer_type,
                        "sanitizer_code": line.strip(),
                        "sanitizer_pattern": pattern,
                        "sanitized_variable": sanitized_var,
                        "context": sanitizer_context
                    })
    
    return identified_sanitizers

def track_function_calls(ast_data, content, language):
    """
    Track function calls in the code to understand data flow between functions.
    """
    function_calls = []
    
    # Extract function calls from AST nodes
    for node in ast_data.get("nodes", []):
        if node.get("type") in ["Call", "CallExpression", "MethodInvocation"]:
            line = get_line_number(node, content)
            
            # Get function name based on language
            func_name = ""
            args = []
            
            if language == "python":
                if "func" in node:
                    func = node.get("func", {})
                    if func.get("type") == "Name":
                        func_name = func.get("id", "")
                    elif func.get("type") == "Attribute":
                        func_name = func.get("attr", "")
                args = node.get("args", [])
            
            elif language in ["javascript", "typescript"]:
                if "callee" in node:
                    callee = node.get("callee", {})
                    if callee.get("type") == "Identifier":
                        func_name = callee.get("name", "")
                    elif callee.get("type") == "MemberExpression":
                        obj = callee.get("object", {}).get("name", "")
                        prop = callee.get("property", {}).get("name", "")
                        func_name = f"{obj}.{prop}"
                args = node.get("arguments", [])
            
            elif language == "java":
                if "name" in node:
                    func_name = node.get("name", "")
                args = node.get("arguments", [])
            
            # Fallback to extract function name from content
            if not func_name:
                code_snippet = extract_code_snippet(content, line)
                call_match = re.search(r'(\w+(?:\.\w+)*)\s*\(', code_snippet)
                if call_match:
                    func_name = call_match.group(1)
            
            # Add to function calls
            function_calls.append({
                "line": line,
                "function": func_name,
                "args": args,
                "code": extract_code_snippet(content, line)
            })
    
    return function_calls

def identify_validation_attempts(ast_data, content, language, pattern_analysis=None):
    """
    Identify validation attempts that might be bypassed.
    """
    validation_attempts = []
    lines = content.split('\n')
    
    # Patterns that indicate validation
    validation_patterns = [
        r'if\s*\(',
        r'validate',
        r'sanitize',
        r'check',
        r'assert',
        r'verify'
    ]
    
    # Add validation functions from pattern analysis
    if pattern_analysis and "validation_functions" in pattern_analysis:
        for func in pattern_analysis["validation_functions"]:
            validation_patterns.append(re.escape(func))
    
    # Look for validation patterns
    for i, line in enumerate(lines):
        line_num = i + 1
        for pattern in validation_patterns:
            if re.search(pattern, line):
                # Get context to analyze the validation
                validation_context = get_context(content, line_num, 4)
                
                # Try to identify what's being validated
                validated_input = None
                validation_code = line.strip()
                
                # Analyze the validation for potential bypasses
                potential_bypass = analyze_validation_for_bypasses(validation_context, language)
                
                # Try to determine the source of the input being validated
                input_line = find_input_source(validation_context, line_num, content)
                
                validation_attempts.append({
                    "line": line_num,
                    "validation_code": validation_code,
                    "validated_input": validated_input,
                    "context": validation_context,
                    "potential_bypass": potential_bypass,
                    "input_line": input_line
                })
    
    return validation_attempts

def analyze_validation_for_bypasses(validation_context, language):
    """
    Analyze validation code for potential bypasses.
    """
    potential_bypasses = []
    
    # Common validation bypass patterns
    bypass_patterns = {
        "incomplete_type_check": r'typeof\s+(\w+)\s*===\s*[\'"](\w+)[\'"]',
        "null_bypass": r'if\s*\(\s*(\w+)\s*(!?=+)\s*(null|undefined)',
        "length_check_only": r'(\w+)\.length\s*([<>=]+)\s*\d+',
        "string_comparison": r'(\w+)\s*===\s*[\'"][^\'"]*[\'"]',
        "whitelist_only": r'(indexOf|includes)\s*\(',
        "regex_without_anchors": r'\/[^\^].*[^$]\/[gimuy]*\.test\s*\(',
        "case_insensitive_check": r'(?i)\.toLowerCase\(\)\s*===',
    }
    
    for bypass_type, pattern in bypass_patterns.items():
        matches = re.finditer(pattern, validation_context)
        for match in matches:
            if bypass_type == "incomplete_type_check":
                var_name, type_name = match.groups()
                potential_bypasses.append(f"Type check for '{var_name}' can be bypassed by providing values of the right type but malicious content")
            
            elif bypass_type == "null_bypass":
                var_name = match.group(1)
                potential_bypasses.append(f"Null check for '{var_name}' doesn't validate the actual content if provided")
            
            elif bypass_type == "length_check_only":
                var_name = match.group(1)
                potential_bypasses.append(f"Length check for '{var_name}' doesn't validate the content")
            
            elif bypass_type == "string_comparison":
                var_name = match.group(1)
                potential_bypasses.append(f"Exact string comparison for '{var_name}' could be bypassed with alternative encodings or case differences")
            
            elif bypass_type == "whitelist_only":
                potential_bypasses.append(f"Whitelist check using {match.group(1)} can be bypassed if the list is incomplete")
            
            elif bypass_type == "regex_without_anchors":
                potential_bypasses.append("Regex without proper anchors (^ and $) can be bypassed by adding content before or after the pattern")
            
            elif bypass_type == "case_insensitive_check":
                potential_bypasses.append("Case-insensitive comparison can be bypassed if Unicode normalization is not considered")
    
    # Look for validation that doesn't check all possible attack vectors
    vector_patterns = {
        "sql_injection": [r'SELECT', r'INSERT', r'UPDATE', r'DELETE', r'DROP', r'UNION'],
        "xss": [r'<script', r'onerror', r'javascript:', r'eval\('],
        "command_injection": [r';', r'&&', r'\|\|', r'`']
    }
    
    for vector_type, patterns in vector_patterns.items():
        checks_found = []
        for pattern in patterns:
            if re.search(pattern, validation_context, re.IGNORECASE):
                checks_found.append(pattern)
        
        if checks_found and len(checks_found) < len(patterns):
            missing = set(patterns) - set(checks_found)
            potential_bypasses.append(f"{vector_type} validation may be incomplete - missing checks for: {', '.join(missing)}")
    
    return potential_bypasses if potential_bypasses else "No obvious bypasses detected"

def find_input_source(context, validation_line, full_content):
    """
    Try to find the source of the input being validated.
    """
    lines = full_content.split('\n')
    
    # Look for variable names in the validation
    var_matches = re.finditer(r'(\w+)\s*(?:===|!==|==|!=|>=|<=|>|<|\bin\b)', context)
    potential_vars = [match.group(1) for match in var_matches]
    
    # Look for recent assignments to these variables
    for i in range(validation_line - 1, 0, -1):
        line = lines[i-1] if i <= len(lines) else ""
        for var in potential_vars:
            if re.search(rf'\b{var}\b\s*=', line):
                return i
    
    # If no clear assignment is found, return an estimate
    return max(1, validation_line - 5)

def identify_suspicious_patterns(ast_data, content, language, pattern_analysis=None):
    """
    Identify suspicious code patterns that might indicate vulnerabilities.
    """
    suspicious_patterns = []
    lines = content.split('\n')
    
    # Common suspicious patterns
    pattern_checks = {
        "dynamic_code_execution": [
            r'eval\s*\(', 
            r'Function\s*\(.*\)',
            r'setTimeout\s*\(\s*[\'"`]',
            r'setInterval\s*\(\s*[\'"`]',
            r'new\s+Function\s*\('
        ],
        "direct_object_references": [
            r'getElementById\s*\(\s*.*\s*\+',
            r'getElementByName\s*\(\s*.*\s*\+',
            r'querySelector\s*\(\s*.*\s*\+',
            r'find\s*\(\s*.*\s*\+',
            r'findOne\s*\(\s*.*\s*\+'
        ],
        "hardcoded_credentials": [
            r'password\s*=\s*[\'"`][^\'"]+[\'"`]',
            r'apiKey\s*=\s*[\'"`][^\'"]+[\'"`]',
            r'secret\s*=\s*[\'"`][^\'"]+[\'"`]',
            r'credentials\s*=\s*[\'"`][^\'"]+[\'"`]',
            r'key\s*=\s*[\'"`][^\'"]+[\'"`]'
        ],
        "insecure_configuration": [
            r'debug\s*=\s*true',
            r'validateCertificate\s*=\s*false',
            r'verify\s*=\s*false',
            r'allowUnsafeEval',
            r'allowUnsafeHtml'
        ],
        "weak_crypto": [
            r'md5\(',
            r'createHash\s*\(\s*[\'"]md5[\'"]',
            r'sha1\(',
            r'createHash\s*\(\s*[\'"]sha1[\'"]',
            r'Math\.random\s*\(',
            r'new\s+Date\(\)\.getTime\(\)'
        ],
        "race_conditions": [
            r'setTimeout\s*\(\s*function\s*\(\s*\)\s*{\s*.*\s*}\s*,\s*0\s*\)',
            r'process\.nextTick',
            r'setImmediate\s*\(',
            r'requestAnimationFrame\s*\('
        ]
    }
    
    # Add suspicious patterns from project analysis
    if pattern_analysis and "custom_functions" in pattern_analysis:
        for name, info in pattern_analysis.get("custom_functions", {}).items():
            impact = info.get("potential_security_impact", "").lower()
            if "unsafe" in impact or "vulnerable" in impact or "risky" in impact:
                pattern_checks.setdefault("custom_suspicious", []).append(re.escape(name))
    
    # Check for suspicious patterns
    for pattern_type, patterns in pattern_checks.items():
        for pattern in patterns:
            for i, line in enumerate(lines):
                line_num = i + 1
                if re.search(pattern, line):
                    suspicious_patterns.append({
                        "type": pattern_type,
                        "line": line_num,
                        "code": line.strip(),
                        "pattern": pattern,
                        "description": get_description_for_pattern(pattern_type, pattern),
                        "context": get_context(content, line_num, 2)
                    })
    
    # Look for more complex suspicious patterns
    
    # Check for obfuscated code
    for i, line in enumerate(lines):
        line_num = i + 1
        
        # Check for string splitting and joining
        if re.search(r'\[[\'"][^\'"]*[\'"]\s*\+\s*[\'"][^\'"]*[\'"]\]', line) or \
           re.search(r'String\.fromCharCode\s*\(', line) or \
           re.search(r'(\\x[0-9a-fA-F]{2}){3,}', line):
            
            suspicious_patterns.append({
                "type": "obfuscated_code",
                "line": line_num,
                "code": line.strip(),
                "pattern": "obfuscated_strings",
                "description": "Potentially obfuscated code that might hide malicious functionality",
                "context": get_context(content, line_num, 2)
            })
    
    # Check for dangerous global modifications
    for i, line in enumerate(lines):
        line_num = i + 1
        
        if re.search(r'Object\.prototype\s*\.', line) or \
           re.search(r'Array\.prototype\s*\.', line) or \
           re.search(r'String\.prototype\s*\.', line) or \
           re.search(r'__proto__\s*=', line):
            
            suspicious_patterns.append({
                "type": "prototype_pollution",
                "line": line_num,
                "code": line.strip(),
                "pattern": "prototype_modification",
                "description": "Modification of object prototypes that could lead to prototype pollution vulnerabilities",
                "context": get_context(content, line_num, 2)
            })
    
    return suspicious_patterns

def get_description_for_pattern(pattern_type, pattern):
    """
    Get a description for a suspicious pattern.
    """
    descriptions = {
        "dynamic_code_execution": "Dynamic code execution that could lead to code injection vulnerabilities",
        "direct_object_references": "Direct object reference that might be vulnerable to IDOR attacks",
        "hardcoded_credentials": "Hardcoded credentials that should be stored securely in environment variables or a secure vault",
        "insecure_configuration": "Insecure configuration that might weaken security protections",
        "weak_crypto": "Weak cryptographic implementation that might not provide adequate security",
        "race_conditions": "Potential race condition that might lead to timing attacks or inconsistent state",
        "custom_suspicious": "Custom function flagged as potentially security-sensitive"
    }
    
    return descriptions.get(pattern_type, "Suspicious code pattern")

def build_call_graph(ast_data, function_calls, content, language):
    """
    Build a call graph to understand how functions call each other.
    """
    call_graph = {}
    
    # Extract function definitions
    functions = []
    for node in ast_data.get("nodes", []):
        if node.get("type") in ["FunctionDef", "ClassDef", "FunctionDeclaration", "ClassDeclaration"]:
            line = get_line_number(node, content)
            name = node.get("name", "")
            
            if name:
                functions.append({
                    "name": name,
                    "line": line,
                    "type": node.get("type"),
                    "params": node.get("params", []),
                    "calls": []
                })
    
    # Map function calls to definitions
    for call in function_calls:
        func_name = call["function"]
        
        # Find which function contains this call
        containing_func = None
        for func in functions:
            # Simple heuristic: call is within function if line number is after function start
            if call["line"] > func["line"]:
                # If multiple functions match, take the closest one (most nested)
                if containing_func is None or func["line"] > containing_func["line"]:
                    containing_func = func
        
        if containing_func:
            containing_func["calls"].append({
                "name": func_name,
                "line": call["line"],
                "args": call.get("args", [])
            })
    
    # Build the call graph
    for func in functions:
        call_graph[func["name"]] = {
            "line": func["line"],
            "calls": [call["name"] for call in func["calls"]],
            "called_by": []
        }
    
    # Fill in "called_by"
    for func_name, func_info in call_graph.items():
        for called_func in func_info["calls"]:
            if called_func in call_graph:
                call_graph[called_func]["called_by"].append(func_name)
    
    return call_graph

def perform_taint_tracking_enhanced(sources, variables, content, function_calls, call_graph, pattern_analysis=None):
    """
    Track tainted data through variable assignments to identify tainted variables.
    Enhanced to track through function calls and transformations.
    """
    tainted_variables = []
    lines = content.split('\n')
    
    # Custom transformation functions from pattern analysis
    transformation_functions = []
    if pattern_analysis:
        transformation_functions = pattern_analysis.get("data_transformations", [])
    
    # First, mark variables directly assigned from sources as tainted
    for source in sources:
        source_line = source["line"]
        source_code = source["source_code"]
        
        # Find variables assigned at source lines
        for variable in variables:
            if variable["line"] == source_line:
                variable["tainted"] = True
                variable["taint_source"] = source["source_type"]
                tainted_variables.append({
                    "variable": variable["name"],
                    "line": variable["line"],
                    "source": source["source_type"],
                    "code": source_code,
                    "transformations": []
                })
    
    # Add taint to variables assigned from already tainted variables
    # Perform multiple passes to catch chains of assignments
    for i in range(5):  # Do 5 passes for multi-step propagation
        newly_tainted = []
        
        for variable in variables:
            if variable["tainted"]:
                var_name = variable["name"]
                
                # Check if this tainted variable is used in initializers of other variables
                for other_var in variables:
                    if not other_var["tainted"] and var_name in other_var.get("initializer", ""):
                        other_var["tainted"] = True
                        other_var["taint_source"] = variable["taint_source"]
                        
                        # Check if this is a transformation
                        transformations = []
                        for transform_func in transformation_functions:
                            if transform_func in other_var.get("initializer", ""):
                                transformations.append(transform_func)
                        
                        newly_tainted.append({
                            "variable": other_var["name"],
                            "line": other_var["line"],
                            "source": variable["taint_source"],
                            "code": other_var.get("initializer", ""),
                            "transformed_from": var_name,
                            "transformations": transformations
                        })
                
                # Check later assignments to other variables
                for other_var in variables:
                    for assignment in other_var.get("later_assignments", []):
                        if var_name in assignment.get("value", "") and not other_var["tainted"]:
                            other_var["tainted"] = True
                            other_var["taint_source"] = variable["taint_source"]
                            
                            # Check if this is a transformation
                            transformations = []
                            for transform_func in transformation_functions:
                                if transform_func in assignment.get("value", ""):
                                    transformations.append(transform_func)
                            
                            newly_tainted.append({
                                "variable": other_var["name"],
                                "line": assignment["line"],
                                "source": variable["taint_source"],
                                "code": assignment.get("value", ""),
                                "transformed_from": var_name,
                                "transformations": transformations
                            })
        
        tainted_variables.extend(newly_tainted)
        if not newly_tainted:
            break
    
    # Track taint through function calls
    for call in function_calls:
        func_name = call["function"]
        line = call["line"]
        
        # Check if this function call contains tainted variables
        call_code = call.get("code", "")
        tainted_vars_in_call = []
        
        for var in [v for v in variables if v["tainted"]]:
            var_name = var["name"]
            if var_name in call_code:
                tainted_vars_in_call.append(var)
                
                # If the function call is assigned to a variable, that variable is tainted
                assignment_match = re.search(r'(\w+)\s*=\s*.*' + re.escape(func_name), call_code)
                if assignment_match:
                    assigned_var = assignment_match.group(1)
                    
                    # Find the variable
                    for var_obj in variables:
                        if var_obj["name"] == assigned_var:
                            var_obj["tainted"] = True
                            var_obj["taint_source"] = var["taint_source"]
                            
                            # Check if this is a transformation
                            transformations = []
                            if func_name in transformation_functions:
                                transformations.append(func_name)
                            
                            tainted_variables.append({
                                "variable": assigned_var,
                                "line": line,
                                "source": var["taint_source"],
                                "code": call_code,
                                "transformed_from": var_name,
                                "transformations": transformations
                            })
    
    return tainted_variables

def identify_source_sink_flows_enhanced(sources, sinks, tainted_variables, sanitizers, function_calls, call_graph, validation_attempts=None):
    """
    Identify potential security vulnerabilities by finding flows from sources to sinks.
    Enhanced to track complex flows with detailed paths.
    """
    source_sink_flows = []
    
    # For each sink, check if there's a tainted variable flowing to it
    for sink in sinks:
        sink_line = sink["line"]
        sink_code = sink["sink_code"]
        
        # Check each tainted variable
        for tainted in tainted_variables:
            tainted_var = tainted["variable"]
            
            # Check if tainted variable appears in sink code
            if tainted_var in sink_code:
                # Check if there's sanitization between source and sink
                sanitized = False
                used_sanitizers = []
                
                for sanitizer in sanitizers:
                    sanitizer_line = sanitizer["line"]
                    sanitizer_code = sanitizer["sanitizer_code"]
                    sanitized_var = sanitizer.get("sanitized_variable")
                    
                    # Only consider sanitization if:
                    # 1. It's between the source and sink lines
                    # 2. It involves the tainted variable
                    if (tainted["line"] < sanitizer_line < sink_line and 
                        (tainted_var in sanitizer_code or 
                         (sanitized_var and sanitized_var == tainted_var))):
                        
                        sanitized = True
                        used_sanitizers.append({
                            "type": sanitizer["sanitizer_type"],
                            "line": sanitizer_line,
                            "code": sanitizer_code
                        })
                
                # Try to determine the flow path
                flow_path = determine_flow_path(
                    tainted, sink, tainted_variables, function_calls, call_graph
                )
                
                # Check if validation attempts might be bypassed
                validation_bypass = check_validation_bypasses(
                    tainted, sink, validation_attempts if validation_attempts else []
                )
                
                # Create the flow record
                source_sink_flows.append({
                    "source_type": tainted["source"],
                    "source_line": tainted["line"],
                    "source_code": tainted["code"],
                    "sink_type": sink["sink_type"],
                    "sink_line": sink_line,
                    "sink_code": sink_code,
                    "sanitized": sanitized,
                    "sanitizers": used_sanitizers,
                    "variable": tainted_var,
                    "flow_path": flow_path,
                    "transformations": tainted.get("transformations", []),
                    "validation_bypass": validation_bypass
                })
    
    return source_sink_flows

def determine_flow_path(tainted, sink, tainted_variables, function_calls, call_graph):
    """
    Determine the flow path from source to sink.
    """
    flow_path = [f"Source at line {tainted['line']}"]
    
    # Check if the variable went through any transformations
    if "transformed_from" in tainted:
        flow_path.append(f"Transformed from {tainted['transformed_from']} at line {tainted['line']}")
        
        # Find the original variable
        for var in tainted_variables:
            if var["variable"] == tainted["transformed_from"]:
                if "transformed_from" in var:
                    flow_path.append(f"Originally from {var['transformed_from']} at line {var['line']}")
                break
    
    # Check if there are function calls in the path
    tainted_var = tainted["variable"]
    sink_line = sink["line"]
    
    # Look for function calls between source and sink that use the tainted variable
    relevant_calls = []
    for call in function_calls:
        if tainted["line"] < call["line"] < sink_line and tainted_var in call.get("code", ""):
            relevant_calls.append(call)
    
    # Sort by line number
    relevant_calls.sort(key=lambda x: x["line"])
    
    # Add to flow path
    for call in relevant_calls:
        flow_path.append(f"Passed to {call['function']} at line {call['line']}")
    
    # Add sink
    flow_path.append(f"Reaches sink at line {sink_line}")
    
    return flow_path

def check_validation_bypasses(tainted, sink, validation_attempts):
    """
    Check if validation attempts for this tainted variable might be bypassed.
    """
    tainted_var = tainted["variable"]
    tainted_line = tainted["line"]
    sink_line = sink["line"]
    
    # Find validation attempts between source and sink
    relevant_validations = []
    for validation in validation_attempts:
        validation_line = validation["line"]
        validation_code = validation["validation_code"]
        
        if tainted_line < validation_line < sink_line and tainted_var in validation_code:
            relevant_validations.append(validation)
    
    if not relevant_validations:
        return "No validation attempts detected"
    
    # Check for potential bypasses
    bypasses = []
    for validation in relevant_validations:
        if isinstance(validation["potential_bypass"], list):
            bypasses.extend(validation["potential_bypass"])
        else:
            bypasses.append(validation["potential_bypass"])
    
    return bypasses if bypasses else "Validation appears to be adequate"

def get_line_number(node, content):
    """
    Get line number from node or estimate it from position in content.
    """
    if "line" in node:
        return node["line"]
    elif "start" in node:
        # Count newlines before the start position
        return content[:node["start"]].count('\n') + 1
    return 0

def extract_code_snippet(content, line_number):
    """
    Extract the code snippet at a given line number.
    """
    lines = content.split('\n')
    if 1 <= line_number <= len(lines):
        return lines[line_number - 1].strip()
    return ""

def get_context(content, line_number, context_lines=2):
    """
    Get context around a specific line.
    """
    lines = content.split('\n')
    
    # Calculate start and end lines
    start = max(0, line_number - context_lines - 1)
    end = min(len(lines) - 1, line_number + context_lines - 1)
    
    # Extract context lines
    context = '\n'.join(lines[start:end+1])
    
    return context