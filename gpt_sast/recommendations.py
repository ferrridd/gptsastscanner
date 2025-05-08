import json
import logging

def get_security_recommendations(openai, model, vulnerabilities, vulnerability_types):
    """
    Get comprehensive recommendations for fixing the identified vulnerabilities.
    Returns a list of recommendations.
    """
    logger = logging.getLogger('gpt_sast.recommendations')
    
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
                "description": v.get("description", "")
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
    
    Return the recommendations as a JSON array:
    [
      {{
        "vulnerability_type": "type",
        "risk_explanation": "detailed explanation of the security risk and impact",
        "vulnerable_code_patterns": "patterns to avoid",
        "secure_code_examples": "secure code patterns to use instead",
        "best_practices": "best practices to prevent this vulnerability",
        "security_references": ["OWASP link", "CWE link", etc.],
        "affected_files": ["file1", "file2", ...]
      }}
    ]
    """
    
    try:
        response = openai.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a security expert providing detailed remediation recommendations."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=4000
        )
        
        # Parse the JSON response
        recommendations = json.loads(response.choices[0].message.content)
        
        # Add affected files to each recommendation
        for rec in recommendations:
            vuln_type = rec.get("vulnerability_type", "")
            affected_files = list(set([v.get("file", "") for v in vulnerabilities 
                                     if v.get("vulnerability_type") == vuln_type]))
            rec["affected_files"] = affected_files
        
        return recommendations
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing recommendations: {str(e)}")
        logger.debug(f"Raw response: {response.choices[0].message.content}")
        return []
    except Exception as e:
        logger.error(f"Error getting recommendations: {str(e)}")
        return []