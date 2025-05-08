import logging
import os
import re
import json
import tempfile
import subprocess

logger = logging.getLogger('gpt_sast.ast_parser')

def parse_code_to_ast(file_path, content, language):
    """
    Parse code into an abstract syntax tree (AST) representation.
    Uses language-specific parsers when available, or falls back to regex-based pseudo AST.
    
    Returns a dictionary with AST nodes.
    """
    try:
        if language == "python":
            return parse_python_ast(content)
        elif language in ["javascript", "typescript"]:
            return parse_js_ast(content)
        elif language == "java":
            return parse_java_ast(content)
        else:
            # Fallback to simple regex-based pseudo AST
            return parse_generic_ast(content, language)
    except Exception as e:
        logger.warning(f"Error parsing AST for {file_path}: {str(e)}")
        # Return empty AST on failure
        return {"nodes": []}

def parse_python_ast(content):
    """
    Parse Python code into AST using Python's built-in ast module.
    """
    try:
        import ast as python_ast
        
        # Parse the content into AST
        tree = python_ast.parse(content)
        
        # Convert AST to a serializable format
        nodes = []
        
        class NodeVisitor(python_ast.NodeVisitor):
            def generic_visit(self, node):
                node_info = {
                    "type": node.__class__.__name__,
                    "line": getattr(node, "lineno", 0),
                    "col": getattr(node, "col_offset", 0)
                }
                
                # Add specific attributes for different node types
                if isinstance(node, python_ast.Assign):
                    node_info["targets"] = []
                    for target in node.targets:
                        if isinstance(target, python_ast.Name):
                            node_info["targets"].append({
                                "type": "Name",
                                "id": target.id
                            })
                    
                    # Add basic info about the value
                    if isinstance(node.value, python_ast.Constant):
                        node_info["value"] = {
                            "type": "Constant",
                            "value_type": type(node.value.value).__name__
                        }
                    else:
                        node_info["value"] = {
                            "type": node.value.__class__.__name__
                        }
                
                elif isinstance(node, python_ast.Call):
                    if isinstance(node.func, python_ast.Name):
                        node_info["func"] = {
                            "type": "Name",
                            "id": node.func.id
                        }
                    elif isinstance(node.func, python_ast.Attribute):
                        if isinstance(node.func.value, python_ast.Name):
                            node_info["func"] = {
                                "type": "Attribute",
                                "attr": node.func.attr,
                                "value": {
                                    "type": "Name",
                                    "id": node.func.value.id
                                }
                            }
                
                elif isinstance(node, python_ast.FunctionDef):
                    node_info["name"] = node.name
                    
                    # Extract arguments
                    node_info["args"] = {
                        "args": [arg.arg for arg in node.args.args],
                        "defaults": [None] * (len(node.args.args) - len(node.args.defaults)) + [True] * len(node.args.defaults)
                    }
                
                # Extract imports
                elif isinstance(node, (python_ast.Import, python_ast.ImportFrom)):
                    if isinstance(node, python_ast.Import):
                        node_info["names"] = [{"name": alias.name, "asname": alias.asname} for alias in node.names]
                    else:  # ImportFrom
                        node_info["module"] = node.module
                        node_info["names"] = [{"name": alias.name, "asname": alias.asname} for alias in node.names]
                
                nodes.append(node_info)
                super().generic_visit(node)
        
        # Visit all nodes
        visitor = NodeVisitor()
        visitor.visit(tree)
        
        return {"nodes": nodes}
    except Exception as e:
        logger.warning(f"Error parsing Python AST: {str(e)}")
        return {"nodes": []}

def parse_js_ast(content):
    """
    Parse JavaScript/TypeScript code into AST using esprima/acorn or simple regex.
    """
    # Simple regex-based approach for demonstration
    nodes = []
    
    # Find variable declarations (var, let, const)
    var_pattern = r'(var|let|const)\s+(\w+)\s*=\s*([^;]+);'
    for match in re.finditer(var_pattern, content):
        keyword, name, value = match.groups()
        line_num = content[:match.start()].count('\n') + 1
        
        nodes.append({
            "type": "VariableDeclaration",
            "kind": keyword,
            "line": line_num,
            "declarations": [{
                "type": "VariableDeclarator",
                "id": {"type": "Identifier", "name": name},
                "init": {"type": "Expression", "raw": value.strip()}
            }]
        })
    
    # Find function declarations
    func_pattern = r'function\s+(\w+)\s*\(([^)]*)\)\s*\{'
    for match in re.finditer(func_pattern, content):
        name, params = match.groups()
        line_num = content[:match.start()].count('\n') + 1
        
        nodes.append({
            "type": "FunctionDeclaration",
            "line": line_num,
            "id": {"type": "Identifier", "name": name},
            "params": [{"type": "Identifier", "name": p.strip()} for p in params.split(',') if p.strip()]
        })
    
    # Find method calls
    call_pattern = r'(\w+(?:\.\w+)*)\s*\(([^)]*)\)'
    for match in re.finditer(call_pattern, content):
        caller, args = match.groups()
        line_num = content[:match.start()].count('\n') + 1
        
        if '.' in caller:
            obj, method = caller.rsplit('.', 1)
            nodes.append({
                "type": "CallExpression",
                "line": line_num,
                "callee": {
                    "type": "MemberExpression",
                    "object": {"type": "Identifier", "name": obj},
                    "property": {"type": "Identifier", "name": method}
                },
                "arguments": [{"type": "Expression", "raw": arg.strip()} for arg in args.split(',') if arg.strip()]
            })
        else:
            nodes.append({
                "type": "CallExpression",
                "line": line_num,
                "callee": {"type": "Identifier", "name": caller},
                "arguments": [{"type": "Expression", "raw": arg.strip()} for arg in args.split(',') if arg.strip()]
            })
    
    # Find assignments
    assign_pattern = r'(\w+(?:\.\w+)*)\s*=\s*([^;]+);'
    for match in re.finditer(assign_pattern, content):
        left, right = match.groups()
        line_num = content[:match.start()].count('\n') + 1
        
        if '.' in left:
            obj, prop = left.rsplit('.', 1)
            nodes.append({
                "type": "AssignmentExpression",
                "line": line_num,
                "left": {
                    "type": "MemberExpression",
                    "object": {"type": "Identifier", "name": obj},
                    "property": {"type": "Identifier", "name": prop}
                },
                "right": {"type": "Expression", "raw": right.strip()}
            })
        else:
            nodes.append({
                "type": "AssignmentExpression",
                "line": line_num,
                "left": {"type": "Identifier", "name": left},
                "right": {"type": "Expression", "raw": right.strip()}
            })
    
    return {"nodes": nodes}

def parse_java_ast(content):
    """
    Parse Java code into AST using simple regex patterns (simplified for demonstration).
    """
    nodes = []
    
    # Find class declarations
    class_pattern = r'(public|private|protected)?\s+class\s+(\w+)(?:\s+extends\s+(\w+))?(?:\s+implements\s+([\w,\s]+))?\s*\{'
    for match in re.finditer(class_pattern, content):
        modifier, name, extends, implements = match.groups()
        line_num = content[:match.start()].count('\n') + 1
        
        nodes.append({
            "type": "ClassDeclaration",
            "line": line_num,
            "modifier": modifier if modifier else "",
            "name": name,
            "extends": extends if extends else "",
            "implements": [impl.strip() for impl in implements.split(',')] if implements else []
        })
    
    # Find method declarations
    method_pattern = r'(public|private|protected)?\s+(static)?\s+(\w+)\s+(\w+)\s*\(([^)]*)\)\s*(?:throws\s+([\w,\s]+))?\s*\{'
    for match in re.finditer(method_pattern, content):
        groups = match.groups()
        line_num = content[:match.start()].count('\n') + 1
        
        # Handle cases where some groups might be None
        modifier = groups[0] if groups[0] else ""
        is_static = bool(groups[1])
        return_type = groups[2]
        name = groups[3]
        params = groups[4]
        throws = groups[5] if len(groups) > 5 and groups[5] else ""
        
        nodes.append({
            "type": "MethodDeclaration",
            "line": line_num,
            "modifier": modifier,
            "static": is_static,
            "return_type": return_type,
            "name": name,
            "parameters": [{"type": p.split()[0], "name": p.split()[1] if len(p.split()) > 1 else ""} 
                          for p in params.split(',') if p.strip()],
            "throws": [exc.strip() for exc in throws.split(',')] if throws else []
        })
    
    # Find field declarations
    field_pattern = r'(public|private|protected)?\s+(static)?\s+(final)?\s+(\w+)\s+(\w+)\s*(?:=\s*([^;]+))?;'
    for match in re.finditer(field_pattern, content):
        groups = match.groups()
        line_num = content[:match.start()].count('\n') + 1
        
        modifier = groups[0] if groups[0] else ""
        is_static = bool(groups[1])
        is_final = bool(groups[2])
        field_type = groups[3]
        name = groups[4]
        initializer = groups[5] if len(groups) > 5 and groups[5] else ""
        
        nodes.append({
            "type": "FieldDeclaration",
            "line": line_num,
            "modifier": modifier,
            "static": is_static,
            "final": is_final,
            "field_type": field_type,
            "name": name,
            "initializer": initializer.strip() if initializer else ""
        })
    
    # Find method calls
    call_pattern = r'(\w+(?:\.\w+)*)\s*\(([^)]*)\)'
    for match in re.finditer(call_pattern, content):
        caller, args = match.groups()
        line_num = content[:match.start()].count('\n') + 1
        
        if '.' in caller:
            obj, method = caller.rsplit('.', 1)
            nodes.append({
                "type": "MethodInvocation",
                "line": line_num,
                "expression": {"type": "Name", "identifier": obj},
                "name": method,
                "arguments": [{"type": "Expression", "raw": arg.strip()} for arg in args.split(',') if arg.strip()]
            })
        else:
            nodes.append({
                "type": "MethodInvocation",
                "line": line_num,
                "name": caller,
                "arguments": [{"type": "Expression", "raw": arg.strip()} for arg in args.split(',') if arg.strip()]
            })
    
    # Find variable declarations and assignments
    var_pattern = r'(\w+)\s+(\w+)\s*(?:=\s*([^;]+))?;'
    for match in re.finditer(var_pattern, content):
        var_type, name, value = match.groups()
        line_num = content[:match.start()].count('\n') + 1
        
        nodes.append({
            "type": "VariableDeclaration",
            "line": line_num,
            "variable_type": var_type,
            "name": name,
            "initializer": value.strip() if value else ""
        })
    
    return {"nodes": nodes}

def parse_generic_ast(content, language):
    """
    Parse code into a simplified AST using regex for unsupported languages.
    """
    nodes = []
    
    # Basic parsing for variable definitions
    var_pattern = r'(\w+)\s+(\w+)\s*(?:=\s*([^;]+))?;'
    for match in re.finditer(var_pattern, content):
        var_type, name, value = match.groups()
        line_num = content[:match.start()].count('\n') + 1
        
        nodes.append({
            "type": "VariableDeclaration",
            "line": line_num,
            "variable_type": var_type,
            "name": name,
            "initializer": value.strip() if value else ""
        })
    
    # Basic parsing for function/method definitions
    func_pattern = r'(?:(\w+)\s+)?(\w+)\s*\(([^)]*)\)\s*\{'
    for match in re.finditer(func_pattern, content):
        return_type, name, params = match.groups()
        line_num = content[:match.start()].count('\n') + 1
        
        nodes.append({
            "type": "FunctionDefinition",
            "line": line_num,
            "return_type": return_type if return_type else "",
            "name": name,
            "parameters": [p.strip() for p in params.split(',') if p.strip()]
        })
    
    # Basic parsing for function/method calls
    call_pattern = r'(\w+(?:\.\w+)*)\s*\(([^)]*)\)'
    for match in re.finditer(call_pattern, content):
        caller, args = match.groups()
        line_num = content[:match.start()].count('\n') + 1
        
        nodes.append({
            "type": "FunctionCall",
            "line": line_num,
            "name": caller,
            "arguments": [arg.strip() for arg in args.split(',') if arg.strip()]
        })
    
    # Basic parsing for assignments
    assign_pattern = r'(\w+(?:\.\w+)*)\s*=\s*([^;]+);'
    for match in re.finditer(assign_pattern, content):
        left, right = match.groups()
        line_num = content[:match.start()].count('\n') + 1
        
        nodes.append({
            "type": "Assignment",
            "line": line_num,
            "left": left,
            "right": right.strip()
        })
    
    return {"nodes": nodes}