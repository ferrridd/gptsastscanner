def get_patterns():
    """Web-specific vulnerability patterns for HTML/JS/CSS files."""
    return {
        "xss_vulnerable_inputs": [
            r'<input[^>]*value\s*=\s*[\'"]?\s*\$\{',
            r'<textarea[^>]*>\s*\$\{',
            r'<select[^>]*value\s*=\s*[\'"]?\s*\$\{',
            r'<div[^>]*>\s*\$\{',
            r'<p[^>]*>\s*\$\{',
            r'<span[^>]*>\s*\$\{'
        ],
        "csrf_vulnerable": [
            r'<form[^>]*>(?:(?!csrf|token|nonce).)*<\/form>',
            r'fetch\s*\([^,\)]+\)',
            r'ajax\s*\(\s*\{[^\}]*url\s*:',
            r'XMLHttpRequest',
            r'post\s*\([^,\)]+\)',
            r'put\s*\([^,\)]+\)',
            r'delete\s*\([^,\)]+\)'
        ],
        "insecure_headers": [
            r'Access-Control-Allow-Origin\s*:\s*\*',
            r'Content-Security-Policy\s*:',
            r'X-Frame-Options\s*:',
            r'X-XSS-Protection\s*:\s*0',
            r'Strict-Transport-Security\s*:',
            r'Cache-Control\s*:\s*no-store'
        ],
        "sensitive_data_exposure": [
            r'<input[^>]*type\s*=\s*[\'"]password[\'"][^>]*>',
            r'<input[^>]*type\s*=\s*[\'"]hidden[\'"][^>]*>',
            r'autocomplete\s*=\s*[\'"]on[\'"]',
            r'placeholder\s*=\s*[\'"]password[\'"]',
            r'placeholder\s*=\s*[\'"]credit[\'"]',
            r'placeholder\s*=\s*[\'"]ssn[\'"]'
        ],
        "dom_based_vulnerabilities": [
            r'document\.URL',
            r'document\.documentURI',
            r'document\.location',
            r'document\.referrer',
            r'window\.location',
            r'window\.name',
            r'location\.href',
            r'location\.search',
            r'location\.hash',
            r'location\.pathname'
        ],
        "open_redirect": [
            r'window\.location\s*=\s*.*\+',
            r'window\.location\.href\s*=\s*.*\+',
            r'window\.location\.replace\s*\(.*\+',
            r'document\.location\s*=\s*.*\+',
            r'location\.assign\s*\(.*\+',
            r'location\s*=\s*.*\+'
        ],
        "client_side_validation_only": [
            r'onsubmit\s*=\s*[\'"].*validate',
            r'validate\w*\s*\(\s*\)',
            r'checkForm\s*\(\s*\)',
            r'verifyInput\s*\(\s*\)',
            r'validateForm\s*\(\s*\)'
        ],
        "insecure_cookies": [
            r'document\.cookie\s*=',
            r'Set-Cookie:(?!.*HttpOnly)',
            r'Set-Cookie:(?!.*Secure)',
            r'Set-Cookie:(?!.*SameSite)',
            r'Cookie\s*:\s*[\'"][^\'"]+[\'"]'
        ],
        "clickjacking_vulnerable": [
            r'iframe\s+src\s*=',
            r'X-Frame-Options\s*:\s*ALLOW',
            r'frame\s+src\s*='
        ],
        "unsafe_third_party": [
            r'src\s*=\s*[\'"]http://',
            r'src\s*=\s*[\'"]//[^\'"]+[\'"]',
            r'href\s*=\s*[\'"]http://',
            r'<script\s+src\s*=',
            r'<link\s+href\s*='
        ],
        "csp_issues": [
            r'unsafe-inline',
            r'unsafe-eval',
            r'Content-Security-Policy\s*:\s*[^\n]*data:',
            r'Content-Security-Policy-Report-Only',
            r'Content-Security-Policy\s*:\s*default-src\s+[\'"]?\*[\'"]?'
        ]
    }