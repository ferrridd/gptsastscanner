import json
import logging
import os
from datetime import datetime

logger = logging.getLogger('gpt_sast.reporting')

def generate_html_report(scan_results, output_path):
    """
    Generate an interactive HTML report from scan results.
    Returns the path to the generated report.
    """
    try:
        html_content = create_html_report(scan_results)
        
        # Write the HTML report to a file
        with open(output_path, 'w') as f:
            f.write(html_content)
        
        logger.info(f"HTML report generated: {output_path}")
        return output_path
    except Exception as e:
        logger.error(f"Error generating HTML report: {str(e)}")
        return None

def create_html_report(results):
    """Create a well-structured HTML report."""
    
    # Extract data from results
    project = results.get("project", "Unknown")
    scan_date = results.get("scan_date", "Unknown")
    scan_duration = results.get("scan_duration_seconds", 0)
    files_scanned = results.get("files_scanned", 0)
    vulnerabilities_found = results.get("vulnerabilities_found", 0)
    unique_vuln_types = results.get("unique_vulnerability_types", 0)
    risk_score = results.get("risk_score", 0)
    severity_breakdown = results.get("severity_breakdown", {})
    vulnerabilities = results.get("vulnerabilities", [])
    recommendations = results.get("recommendations", [])
    critical_files = results.get("critical_files", [])
    
    # Group vulnerabilities by type
    vuln_by_type = {}
    for vuln in vulnerabilities:
        vuln_type = vuln.get("vulnerability_type", "Unknown")
        if vuln_type not in vuln_by_type:
            vuln_by_type[vuln_type] = []
        vuln_by_type[vuln_type].append(vuln)
    
    # Create HTML content
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {project}</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f8f9fa;
            color: #343a40;
        }}
        .container {{
            max-width: 1200px;
            padding: 2rem;
            background-color: white;
            box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.1);
            border-radius: 0.5rem;
            margin-top: 2rem;
            margin-bottom: 2rem;
        }}
        h1 {{
            color: #343a40;
            margin-bottom: 1.5rem;
            border-bottom: 3px solid #6c757d;
            padding-bottom: 0.5rem;
        }}
        h2 {{
            color: #495057;
            margin-top: 2rem;
            margin-bottom: 1rem;
            border-left: 5px solid #6c757d;
            padding-left: 1rem;
        }}
        .dashboard-card {{
            background-color: white;
            border-radius: 0.5rem;
            box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
            margin-bottom: 1.5rem;
            padding: 1.5rem;
            transition: transform 0.3s ease;
        }}
        .dashboard-card:hover {{
            transform: translateY(-5px);
        }}
        .dashboard-card h3 {{
            margin-top: 0;
            font-size: 1.25rem;
            color: #495057;
        }}
        .card-value {{
            font-size: 2.5rem;
            font-weight: 600;
            color: #343a40;
        }}
        .severity-high {{
            background-color: #f8d7da;
            color: #721c24;
        }}
        .severity-medium {{
            background-color: #fff3cd;
            color: #856404;
        }}
        .severity-low {{
            background-color: #d1ecf1;
            color: #0c5460;
        }}
        .badge-critical {{
            background-color: #dc3545;
        }}
        .badge-high {{
            background-color: #fd7e14;
        }}
        .badge-medium {{
            background-color: #ffc107;
            color: #212529;
        }}
        .badge-low {{
            background-color: #17a2b8;
        }}
        .vuln-card {{
            margin-bottom: 1rem;
            border-left: 5px solid #6c757d;
        }}
        .vuln-card.critical {{
            border-left-color: #dc3545;
        }}
        .vuln-card.high {{
            border-left-color: #fd7e14;
        }}
        .vuln-card.medium {{
            border-left-color: #ffc107;
        }}
        .vuln-card.low {{
            border-left-color: #17a2b8;
        }}
        .code-snippet {{
            font-family: SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
            padding: 0.5rem;
            background-color: #f8f9fa;
            border-radius: 0.25rem;
            margin-top: 0.5rem;
            margin-bottom: 0.5rem;
            overflow-x: auto;
        }}
        .chart-container {{
            height: 300px;
            margin-bottom: 2rem;
        }}
        .file-list {{
            max-height: 200px;
            overflow-y: auto;
            font-size: 0.875rem;
        }}
        .vuln-type-header {{
            cursor: pointer;
            padding: 10px;
            background-color: #f1f1f1;
            margin-top: 20px;
            border-radius: 5px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .vuln-details {{
            display: none;
            padding: 10px;
            border: 1px solid #ddd;
            border-top: none;
            border-radius: 0 0 5px 5px;
        }}
        .accordion-button::after {{
            flex-shrink: 0;
            width: 1.25rem;
            height: 1.25rem;
            margin-left: auto;
            content: "";
            background-image: url("data:image/svg+xml,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='%230c63e4'%3e%3cpath fill-rule='evenodd' d='M1.646 4.646a.5.5 0 0 1 .708 0L8 10.293l5.646-5.647a.5.5 0 0 1 .708.708l-6 6a.5.5 0 0 1-.708 0l-6-6a.5.5 0 0 1 0-.708z'/%3e%3c/svg%3e");
            background-repeat: no-repeat;
            background-size: 1.25rem;
            transition: transform .2s ease-in-out;
        }}
        .accordion-button:not(.collapsed)::after {{
            transform: rotate(180deg);
        }}
        .confidence-high {{ 
            background-color: #d4edda; 
            color: #155724; 
        }}
        .confidence-medium {{ 
            background-color: #fff3cd; 
            color: #856404; 
        }}
        .confidence-low {{ 
            background-color: #f8d7da; 
            color: #721c24; 
        }}
        .confidence-indicator {{
            display: inline-block;
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            font-size: 0.75rem;
            font-weight: bold;
        }}
        .taint-flow-diagram {{
            margin: 20px 0;
            padding: 15px;
            border: 1px solid #dee2e6;
            border-radius: 5px;
            background-color: #f8f9fa;
        }}
        .taint-flow-step {{
            margin: 10px 0;
            padding: 10px;
            border-left: 3px solid #6c757d;
            background-color: #fff;
        }}
        .filter-controls {{
            margin-bottom: 20px;
            padding: 15px;
            border-radius: 5px;
            background-color: #f8f9fa;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1 class="text-center">
            Security Scan Report
            <span class="badge bg-secondary">GPT-SAST Scanner</span>
        </h1>
        
        <div class="row mt-4">
            <div class="col-md-6">
                <div class="dashboard-card">
                    <h3>Project Information</h3>
                    <table class="table">
                        <tbody>
                            <tr>
                                <th>Project Path:</th>
                                <td>{project}</td>
                            </tr>
                            <tr>
                                <th>Scan Date:</th>
                                <td>{scan_date}</td>
                            </tr>
                            <tr>
                                <th>Scan Duration:</th>
                                <td>{scan_duration:.2f} seconds</td>
                            </tr>
                            <tr>
                                <th>Files Scanned:</th>
                                <td>{files_scanned}</td>
                            </tr>
                            <tr>
                                <th>Generated by:</th>
                                <td>GPT-SAST Scanner with Data Flow Analysis</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
            <div class="col-md-6">
                <div class="dashboard-card">
                    <h3>Risk Assessment</h3>
                    <div class="row">
                        <div class="col-md-6 text-center">
                            <div class="card-value" id="risk-score">{risk_score}</div>
                            <div>Risk Score</div>
                            <div class="progress mt-2" style="height: 10px;">
                                <div class="progress-bar bg-danger" role="progressbar" style="width: {risk_score}%" aria-valuenow="{risk_score}" aria-valuemin="0" aria-valuemax="100"></div>
                            </div>
                        </div>
                        <div class="col-md-6 text-center">
                            <div class="card-value" id="vuln-count">{vulnerabilities_found}</div>
                            <div>Vulnerabilities</div>
                        </div>
                    </div>
                    <div class="mt-3">
                        <div class="progress" style="height: 30px;">
"""
    
    # Add progress bars for severity breakdown
    total_vulns = sum(severity_breakdown.values())
    if total_vulns > 0:
        if severity_breakdown.get("Critical", 0) > 0:
            critical_percent = (severity_breakdown.get("Critical", 0) / total_vulns) * 100
            html += f'<div class="progress-bar bg-danger" role="progressbar" style="width: {critical_percent}%" aria-valuenow="{critical_percent}" aria-valuemin="0" aria-valuemax="100">Critical: {severity_breakdown.get("Critical", 0)}</div>'
        
        if severity_breakdown.get("High", 0) > 0:
            high_percent = (severity_breakdown.get("High", 0) / total_vulns) * 100
            html += f'<div class="progress-bar bg-warning" role="progressbar" style="width: {high_percent}%" aria-valuenow="{high_percent}" aria-valuemin="0" aria-valuemax="100">High: {severity_breakdown.get("High", 0)}</div>'
        
        if severity_breakdown.get("Medium", 0) > 0:
            medium_percent = (severity_breakdown.get("Medium", 0) / total_vulns) * 100
            html += f'<div class="progress-bar bg-info" role="progressbar" style="width: {medium_percent}%" aria-valuenow="{medium_percent}" aria-valuemin="0" aria-valuemax="100">Medium: {severity_breakdown.get("Medium", 0)}</div>'
        
        if severity_breakdown.get("Low", 0) > 0:
            low_percent = (severity_breakdown.get("Low", 0) / total_vulns) * 100
            html += f'<div class="progress-bar bg-success" role="progressbar" style="width: {low_percent}%" aria-valuenow="{low_percent}" aria-valuemin="0" aria-valuemax="100">Low: {severity_breakdown.get("Low", 0)}</div>'
    
    html += """
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="row">
            <div class="col-md-6">
                <div class="dashboard-card">
                    <h3>Vulnerability Types</h3>
                    <div class="chart-container">
                        <canvas id="vulnTypeChart"></canvas>
                    </div>
                </div>
            </div>
            <div class="col-md-6">
                <div class="dashboard-card">
                    <h3>Most Vulnerable Files</h3>
                    <div class="chart-container">
                        <canvas id="fileVulnChart"></canvas>
                    </div>
                </div>
            </div>
        </div>
        
        <h2>Vulnerabilities by Type</h2>
        
        <div class="filter-controls">
            <div class="row">
                <div class="col-md-3">
                    <label for="severity-filter" class="form-label">Filter by Severity:</label>
                    <select id="severity-filter" class="form-select">
                        <option value="all">All Severities</option>
                        <option value="Critical">Critical</option>
                        <option value="High">High</option>
                        <option value="Medium">Medium</option>
                        <option value="Low">Low</option>
                    </select>
                </div>
                <div class="col-md-3">
                    <label for="confidence-filter" class="form-label">Filter by Confidence:</label>
                    <select id="confidence-filter" class="form-select">
                        <option value="all">All Confidence Levels</option>
                        <option value="high">High Confidence (>0.8)</option>
                        <option value="medium">Medium Confidence (0.5-0.8)</option>
                        <option value="low">Low Confidence (<0.5)</option>
                    </select>
                </div>
                <div class="col-md-4">
                    <label for="file-filter" class="form-label">Filter by File:</label>
                    <select id="file-filter" class="form-select">
                        <option value="all">All Files</option>
"""
    
    # Add files to filter
    files_with_vulns = sorted(set(os.path.basename(v.get("file", "")) for v in vulnerabilities))
    for file in files_with_vulns:
        if file:
            html += f'                        <option value="{file}">{file}</option>\n'
    
    html += """
                    </select>
                </div>
                <div class="col-md-2 d-flex align-items-end">
                    <button id="reset-filters" class="btn btn-secondary w-100">Reset Filters</button>
                </div>
            </div>
        </div>
        
        <div class="accordion" id="vulnAccordion">
"""
    
    # Add vulnerabilities by type
    for i, (vuln_type, vulns) in enumerate(vuln_by_type.items()):
        vuln_count = len(vulns)
        severity_counts = {
            "Critical": sum(1 for v in vulns if v.get("severity") == "Critical"),
            "High": sum(1 for v in vulns if v.get("severity") == "High"),
            "Medium": sum(1 for v in vulns if v.get("severity") == "Medium"),
            "Low": sum(1 for v in vulns if v.get("severity") == "Low")
        }
        
        html += f"""
        <div class="accordion-item vuln-type-item" data-vuln-type="{vuln_type}">
            <h2 class="accordion-header" id="heading{i}">
                <button class="accordion-button{' collapsed' if i > 0 else ''}" type="button" data-bs-toggle="collapse" data-bs-target="#collapse{i}" aria-expanded="{str(i == 0).lower()}" aria-controls="collapse{i}">
                    {vuln_type} <span class="ms-2 badge rounded-pill bg-danger">{vuln_count}</span>
                    <div class="ms-auto me-3">
                        {f'<span class="badge rounded-pill badge-critical ms-1">{severity_counts["Critical"]} Critical</span>' if severity_counts["Critical"] > 0 else ''}
                        {f'<span class="badge rounded-pill badge-high ms-1">{severity_counts["High"]} High</span>' if severity_counts["High"] > 0 else ''}
                        {f'<span class="badge rounded-pill badge-medium ms-1">{severity_counts["Medium"]} Medium</span>' if severity_counts["Medium"] > 0 else ''}
                        {f'<span class="badge rounded-pill badge-low ms-1">{severity_counts["Low"]} Low</span>' if severity_counts["Low"] > 0 else ''}
                    </div>
                </button>
            </h2>
            <div id="collapse{i}" class="accordion-collapse collapse{' show' if i == 0 else ''}" aria-labelledby="heading{i}" data-bs-parent="#vulnAccordion">
                <div class="accordion-body">
"""
        
        # Add each vulnerability in this type
        for j, vuln in enumerate(vulns):
            file_path = vuln.get("file", "")
            file_name = os.path.basename(file_path) if file_path else "Unknown"
            line = vuln.get("line", "")
            severity = vuln.get("severity", "Medium")
            description = vuln.get("description", "")
            code_snippet = vuln.get("code_snippet", "")
            cwe_id = vuln.get("cwe_id", "")
            remediation = vuln.get("remediation", "")
            confidence = vuln.get("confidence", 0.5)
            
            confidence_class = ""
            confidence_text = ""
            if confidence >= 0.8:
                confidence_class = "confidence-high"
                confidence_text = "High"
            elif confidence >= 0.5:
                confidence_class = "confidence-medium"
                confidence_text = "Medium"
            else:
                confidence_class = "confidence-low"
                confidence_text = "Low"
            
            severity_class = ""
            if severity == "Critical":
                severity_class = "critical"
            elif severity == "High":
                severity_class = "high"
            elif severity == "Medium":
                severity_class = "medium"
            else:
                severity_class = "low"
            
            html += f"""
                    <div class="card mb-3 vuln-card {severity_class} vuln-instance" 
                         data-severity="{severity}" 
                         data-confidence="{confidence_text.lower()}" 
                         data-file="{file_name}">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <span>
                                <strong>{file_name}</strong> (Line {line})
                                <span class="badge rounded-pill badge-{severity_class.lower()}">{severity}</span>
                                <span class="confidence-indicator {confidence_class}">{confidence_text} Confidence ({confidence:.2f})</span>
                            </span>
                            <span>
                                {f'<span class="badge bg-secondary">{cwe_id}</span>' if cwe_id else ''}
                            </span>
                        </div>
                        <div class="card-body">
                            <h5 class="card-title">Description</h5>
                            <p class="card-text">{description}</p>
                            
                            <h5 class="card-title">Code</h5>
                            <pre class="code-snippet">{code_snippet}</pre>
                            
                            <h5 class="card-title">Remediation</h5>
                            <p class="card-text">{remediation}</p>
                        </div>
                    </div>
"""
        
        html += """
                </div>
            </div>
        </div>
"""
    
    # Add security recommendations section
    html += """
        <h2>Security Recommendations</h2>
        <div class="accordion" id="recommendationsAccordion">
"""
    
    # Add each recommendation
    for i, rec in enumerate(recommendations):
        vuln_type = rec.get("vulnerability_type", "Unknown")
        risk_explanation = rec.get("risk_explanation", "")
        vulnerable_code_patterns = rec.get("vulnerable_code_patterns", "")
        secure_code_examples = rec.get("secure_code_examples", "")
        best_practices = rec.get("best_practices", "")
        security_references = rec.get("security_references", [])
        affected_files = rec.get("affected_files", [])
        
        html += f"""
        <div class="accordion-item">
            <h2 class="accordion-header" id="headingRec{i}">
                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseRec{i}" aria-expanded="false" aria-controls="collapseRec{i}">
                    {vuln_type}
                </button>
            </h2>
            <div id="collapseRec{i}" class="accordion-collapse collapse" aria-labelledby="headingRec{i}" data-bs-parent="#recommendationsAccordion">
                <div class="accordion-body">
                    <h5>Risk Explanation</h5>
                    <p>{risk_explanation}</p>
                    
                    <h5>Vulnerable Code Patterns</h5>
                    <pre><code class="code-snippet">{vulnerable_code_patterns}</code></pre>
                    
                    <h5>Secure Code Examples</h5>
                    <pre><code class="code-snippet">{secure_code_examples}</code></pre>
                    
                    <h5>Best Practices</h5>
                    <p>{best_practices}</p>
"""
        
        if security_references:
            html += """
                    <h5>Security References</h5>
                    <ul>
"""
            for ref in security_references:
                html += f'                        <li><a href="{ref}" target="_blank">{ref}</a></li>\n'
            
            html += "                    </ul>\n"
        
        if affected_files:
            html += """
                    <h5>Affected Files</h5>
                    <ul class="file-list">
"""
            for file in affected_files:
                file_name = os.path.basename(file) if file else file
                html += f'                        <li>{file_name}</li>\n'
            
            html += "                    </ul>\n"
        
        html += """
                </div>
            </div>
        </div>
"""
    
    # Close remaining HTML tags and add JavaScript for charts and filtering
    html += """
        </div>
        
        <h2>Critical Files</h2>
        <div class="file-list mb-4">
            <div class="table-responsive">
                <table class="table table-striped table-hover">
                    <thead>
                        <tr>
                            <th>File</th>
                            <th>Vulnerabilities</th>
                        </tr>
                    </thead>
                    <tbody>
"""
    
    # Add critical files with vulnerability counts
    for file in critical_files:
        file_name = os.path.basename(file) if file else file
        vuln_count = sum(1 for v in vulnerabilities if v.get("file", "").endswith(file))
        
        severity_class = ""
        if vuln_count > 5:
            severity_class = "table-danger"
        elif vuln_count > 2:
            severity_class = "table-warning"
        elif vuln_count > 0:
            severity_class = "table-info"
        
        html += f"""
                        <tr class="{severity_class}">
                            <td>{file_name}</td>
                            <td>{vuln_count}</td>
                        </tr>
"""
    
    html += """
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Data for charts
        const scanData = """ + json.dumps(results) + """;
        
        // Count vulnerabilities by type
        const vulnByType = {};
        scanData.vulnerabilities.forEach(vuln => {
            const type = vuln.vulnerability_type || 'Unknown';
            vulnByType[type] = (vulnByType[type] || 0) + 1;
        });
        
        // Count vulnerabilities by file
        const vulnByFile = {};
        scanData.vulnerabilities.forEach(vuln => {
            let file = vuln.file ? vuln.file.split('/').pop() : 'Unknown';
            if (!file) file = 'Unknown';
            vulnByFile[file] = (vulnByFile[file] || 0) + 1;
        });
        
        // Sort and limit to top 5 files
        const topFiles = Object.entries(vulnByFile)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5);
        
        // Create vulnerability type chart
        const vulnTypeCtx = document.getElementById('vulnTypeChart').getContext('2d');
        new Chart(vulnTypeCtx, {
            type: 'pie',
            data: {
                labels: Object.keys(vulnByType),
                datasets: [{
                    data: Object.values(vulnByType),
                    backgroundColor: [
                        '#dc3545', '#fd7e14', '#ffc107', '#20c997', '#0dcaf0',
                        '#6f42c1', '#e83e8c', '#6c757d', '#28a745', '#17a2b8',
                        '#343a40', '#007bff', '#6610f2'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            font: {
                                size: 12
                            }
                        }
                    }
                }
            }
        });
        
        // Create vulnerable files chart
        const fileVulnCtx = document.getElementById('fileVulnChart').getContext('2d');
        new Chart(fileVulnCtx, {
            type: 'bar',
            data: {
                labels: topFiles.map(item => item[0]),
                datasets: [{
                    label: 'Vulnerabilities',
                    data: topFiles.map(item => item[1]),
                    backgroundColor: '#007bff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            precision: 0
                        }
                    }
                }
            }
        });
        
        // Filtering functionality
        document.addEventListener('DOMContentLoaded', function() {
            const severityFilter = document.getElementById('severity-filter');
            const confidenceFilter = document.getElementById('confidence-filter');
            const fileFilter = document.getElementById('file-filter');
            const resetButton = document.getElementById('reset-filters');
            
            function applyFilters() {
                const severityValue = severityFilter.value;
                const confidenceValue = confidenceFilter.value;
                const fileValue = fileFilter.value;
                
                // Get all vulnerability instances
                const vulnInstances = document.querySelectorAll('.vuln-instance');
                
                // Get all vulnerability type containers
                const vulnTypes = document.querySelectorAll('.vuln-type-item');
                
                // Reset visibility
                vulnTypes.forEach(type => {
                    type.style.display = 'block';
                });
                
                // Apply filters to vulnerability instances
                vulnInstances.forEach(vuln => {
                    const vulnSeverity = vuln.getAttribute('data-severity');
                    const vulnConfidence = vuln.getAttribute('data-confidence');
                    const vulnFile = vuln.getAttribute('data-file');
                    
                    // Check if the vulnerability passes all filters
                    const passesSeverityFilter = severityValue === 'all' || vulnSeverity === severityValue;
                    const passesConfidenceFilter = confidenceValue === 'all' || vulnConfidence === confidenceValue;
                    const passesFileFilter = fileValue === 'all' || vulnFile === fileValue;
                    
                    // Set visibility based on filter results
                    vuln.style.display = (passesSeverityFilter && passesConfidenceFilter && passesFileFilter) ? 'block' : 'none';
                });
                
                // Hide vulnerability type containers that have no visible vulnerabilities
                vulnTypes.forEach(type => {
                    const visibleVulns = type.querySelectorAll('.vuln-instance[style="display: block;"]');
                    if (visibleVulns.length === 0) {
                        type.style.display = 'none';
                    }
                });
            }
            
            // Add event listeners to filters
            severityFilter.addEventListener('change', applyFilters);
            confidenceFilter.addEventListener('change', applyFilters);
            fileFilter.addEventListener('change', applyFilters);
            
            // Reset filters button
            resetButton.addEventListener('click', function() {
                severityFilter.value = 'all';
                confidenceFilter.value = 'all';
                fileFilter.value = 'all';
                applyFilters();
            });
        });
    </script>
</body>
</html>
"""
    
    return html

def generate_json_report(scan_results, output_path):
    """
    Generate a JSON report from scan results.
    Returns the path to the generated report.
    """
    try:
        with open(output_path, 'w') as f:
            json.dump(scan_results, f, indent=2)
        
        logger.info(f"JSON report generated: {output_path}")
        return output_path
    except Exception as e:
        logger.error(f"Error generating JSON report: {str(e)}")
        return None

def generate_csv_report(scan_results, output_path):
    """
    Generate a CSV report from scan results.
    Returns the path to the generated report.
    """
    try:
        import csv
        
        vulnerabilities = scan_results.get("vulnerabilities", [])
        
        with open(output_path, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow([
                "File", "Line", "Vulnerability Type", "Severity", 
                "Confidence", "Description", "CWE", "Code Snippet", "Remediation"
            ])
            
            # Write vulnerabilities
            for vuln in vulnerabilities:
                writer.writerow([
                    vuln.get("file", ""),
                    vuln.get("line", ""),
                    vuln.get("vulnerability_type", ""),
                    vuln.get("severity", ""),
                    vuln.get("confidence", ""),
                    vuln.get("description", ""),
                    vuln.get("cwe_id", ""),
                    vuln.get("code_snippet", ""),
                    vuln.get("remediation", "")
                ])
        
        logger.info(f"CSV report generated: {output_path}")
        return output_path
    except Exception as e:
        logger.error(f"Error generating CSV report: {str(e)}")
        return None