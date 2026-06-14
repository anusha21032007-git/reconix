"""
report.py

Handles generating and saving vulnerability scan reports in both text and HTML formats.
"""

import os
import datetime
import re
import html
from vulnerabilities import get_vulnerability_info, analyze_ports

def sanitize_target_filename(target: str) -> str:
    """
    Sanitizes target input to prevent directory traversal or invalid filename characters.
    Replaces any character that is not alphanumeric, a dot, or a hyphen with an underscore.
    
    Args:
        target (str): The target host input.
        
    Returns:
        str: Sanitized filename safe string.
    """
    return re.sub(r'[^a-zA-Z0-9.-]', '_', target)

def save_report(target: str, scan_results: dict, banners: dict) -> tuple:
    """
    Generates structured reports (both Text and HTML) and saves them to the reports/ directory.
    
    Args:
        target (str): The scanned hostname or IP address.
        scan_results (dict): Dictionary mapping port to status ('OPEN' or 'CLOSED').
        banners (dict): Dictionary mapping port to grabbed banner text.
        
    Returns:
        tuple: (txt_report_path, html_report_path) absolute paths of the saved reports.
    """
    # Create the reports/ directory if it doesn't exist
    base_dir = os.path.dirname(os.path.abspath(__file__))
    reports_dir = os.path.join(base_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    
    # Generate common filename base with target and timestamp
    sanitized_target = sanitize_target_filename(target)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    txt_filename = f"report_{sanitized_target}_{timestamp}.txt"
    txt_report_path = os.path.join(reports_dir, txt_filename)
    
    html_filename = f"report_{sanitized_target}_{timestamp}.html"
    html_report_path = os.path.join(reports_dir, html_filename)
    
    # Shared variables/calculations for reports
    open_ports = [port for port, status in sorted(scan_results.items()) if status == "OPEN"]
    closed_ports = [port for port, status in sorted(scan_results.items()) if status == "CLOSED"]
    findings = analyze_ports(open_ports)
    scan_time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Calculate target overall risk score based on findings
    severities = [f["severity"] for f in findings]
    if "High" in severities:
        overall_risk = "High"
        overall_risk_color = "#ef4444"  # Red
    elif "Medium" in severities:
        overall_risk = "Medium"
        overall_risk_color = "#f97316"  # Orange
    elif "Low" in severities:
        overall_risk = "Low"
        overall_risk_color = "#3b82f6"  # Blue
    else:
        overall_risk = "Safe"
        overall_risk_color = "#22c55e"  # Green
    
    # ==========================================
    # 1. GENERATE TEXT REPORT
    # ==========================================
    report_lines = []
    report_lines.append("=" * 60)
    report_lines.append("               VULNERABILITY SCANNER REPORT")
    report_lines.append("=" * 60)
    report_lines.append(f"Target Host : {target}")
    report_lines.append(f"Scan Time   : {scan_time_str}")
    report_lines.append("-" * 60)
    report_lines.append("SUMMARY OF SCAN")
    report_lines.append("-" * 60)
    report_lines.append(f"Total Ports Scanned : {len(scan_results)}")
    report_lines.append(f"Open Ports          : {len(open_ports)} ({', '.join(map(str, open_ports)) if open_ports else 'None'})")
    report_lines.append(f"Closed Ports        : {len(closed_ports)}")
    report_lines.append(f"Security Findings   : {len(findings)}")
    report_lines.append(f"Overall Risk Score  : {overall_risk}")
    report_lines.append("-" * 60)
    report_lines.append("PORT DETAILS & FINDINGS")
    report_lines.append("-" * 60)
    
    for port in sorted(scan_results.keys()):
        status = scan_results[port]
        vuln_info = get_vulnerability_info(port)
        service = vuln_info["service"]
        
        report_lines.append(f"[*] Port {port} ({service}): {status}")
        
        if status == "OPEN":
            # Show banner if we have one
            banner = banners.get(port)
            if banner:
                clean_banner = re.sub(r'[\r\n\t]+', ' ', banner).strip()
                report_lines.append(f"    - Service Banner: {clean_banner}")
            
            report_lines.append(f"    - Risk: {vuln_info['description']}")
            report_lines.append(f"    - Recommendation: {vuln_info['recommendation']}")
        report_lines.append("")  # empty line spacer
        
    if findings:
        report_lines.append("-" * 60)
        report_lines.append("SECURITY FINDINGS SUMMARY")
        report_lines.append("-" * 60)
        for finding in findings:
            report_lines.append(f"[{finding['severity'].upper()}] Port {finding['port']}: {finding['message']}")
        report_lines.append("")  # empty line spacer
        
    report_lines.append("=" * 60)
    report_lines.append("End of vulnerability report.")
    report_lines.append("=" * 60)
    
    # Save the text report
    with open(txt_report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(report_lines))
        
    # ==========================================
    # 2. GENERATE HTML REPORT
    # ==========================================
    # Escape dynamic values to prevent XSS (TODO(security): robust output encoding)
    escaped_target = html.escape(target)
    escaped_scan_time = html.escape(scan_time_str)
    
    # Port list table rows
    port_rows_html = []
    for port in sorted(scan_results.keys()):
        status = scan_results[port]
        vuln_info = get_vulnerability_info(port)
        service = html.escape(vuln_info["service"])
        
        status_badge = f'<span class="badge badge-open">Open</span>' if status == "OPEN" else f'<span class="badge badge-closed">Closed</span>'
        
        banner_div = ""
        if status == "OPEN":
            banner = banners.get(port)
            if banner:
                clean_banner = re.sub(r'[\r\n\t]+', ' ', banner).strip()
                banner_div = f'<div class="service-banner">{html.escape(clean_banner)}</div>'
        
        risk_desc = html.escape(vuln_info["description"]) if status == "OPEN" else "N/A"
        recommendation = html.escape(vuln_info["recommendation"]) if status == "OPEN" else "N/A"
        
        row = f"""
        <tr>
            <td style="font-weight: 600;">{port}</td>
            <td>{service}</td>
            <td>{status_badge}</td>
            <td>
                {banner_div}
                <div style="margin-top: { '8px' if banner_div else '0' }; font-size: 13px;">
                    <strong>Risk:</strong> {risk_desc}<br>
                    <strong>Recommendation:</strong> {recommendation}
                </div>
            </td>
        </tr>
        """
        port_rows_html.append(row)
        
    # Findings cards
    findings_html = []
    if findings:
        for finding in findings:
            severity = finding["severity"]  # Expected values: Low, Medium, High
            severity_badge = f'<span class="badge badge-{severity.lower()}">{severity}</span>'
            
            card = f"""
            <div class="finding-card severity-{severity}">
                <div class="finding-content">
                    <div class="finding-title">
                        {severity_badge}
                        <span>Port {finding['port']}</span>
                    </div>
                    <div class="finding-desc">
                        {html.escape(finding['message'])}
                    </div>
                </div>
            </div>
            """
            findings_html.append(card)
    else:
        findings_html.append('<p style="color: var(--text-muted);">No security findings detected for the scanned ports.</p>')
        
    # Combine into full HTML document
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report - {escaped_target}</title>
    <style>
        :root {{
            --primary: #4f46e5;
            --bg-main: #f8fafc;
            --bg-card: #ffffff;
            --text-main: #0f172a;
            --text-muted: #64748b;
            --border: #e2e8f0;
            --severity-high: #ef4444;
            --severity-high-bg: #fef2f2;
            --severity-high-border: #fca5a5;
            --severity-high-text: #991b1b;
            --severity-med: #f97316;
            --severity-med-bg: #fff7ed;
            --severity-med-border: #fdba74;
            --severity-med-text: #c2410c;
            --severity-low: #3b82f6;
            --severity-low-bg: #eff6ff;
            --severity-low-border: #bfdbfe;
            --severity-low-text: #1d4ed8;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg-main);
            color: var(--text-main);
            margin: 0;
            padding: 0;
            line-height: 1.6;
        }}

        .container {{
            max-width: 1000px;
            margin: 40px auto;
            padding: 0 20px;
        }}

        .header {{
            background: linear-gradient(135deg, #1e1b4b 0%, #312e81 100%);
            color: #ffffff;
            padding: 35px;
            border-radius: 16px;
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
            margin-bottom: 30px;
        }}

        .header h1 {{
            margin: 0 0 10px 0;
            font-size: 30px;
            font-weight: 700;
            letter-spacing: -0.025em;
        }}

        .header-meta {{
            display: flex;
            flex-wrap: wrap;
            gap: 24px;
            font-size: 14px;
            color: #c7d2fe;
        }}

        .grid-summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}

        .card-stat {{
            background-color: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 24px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
            text-align: center;
            transition: transform 0.2s, box-shadow 0.2s;
        }}
        
        .card-stat:hover {{
            transform: translateY(-2px);
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1);
        }}

        .stat-value {{
            font-size: 36px;
            font-weight: 700;
            color: var(--primary);
            margin-bottom: 4px;
        }}

        .stat-label {{
            font-size: 13px;
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}

        .section-title {{
            font-size: 22px;
            font-weight: 700;
            margin: 40px 0 20px 0;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--border);
            color: #1e293b;
        }}

        .card-table {{
            background-color: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            overflow: hidden;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
            margin-bottom: 30px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
        }}

        th {{
            background-color: #f8fafc;
            padding: 16px 20px;
            font-size: 13px;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            border-bottom: 1px solid var(--border);
        }}

        td {{
            padding: 20px;
            border-bottom: 1px solid var(--border);
            font-size: 14px;
            vertical-align: top;
        }}

        tr:last-child td {{
            border-bottom: none;
        }}

        .badge {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }}

        .badge-open {{
            background-color: #dcfce7;
            color: #15803d;
        }}

        .badge-closed {{
            background-color: #f1f5f9;
            color: #475569;
        }}

        .badge-high {{
            background-color: var(--severity-high-bg);
            color: var(--severity-high-text);
            border: 1px solid var(--severity-high-border);
        }}

        .badge-medium {{
            background-color: var(--severity-med-bg);
            color: var(--severity-med-text);
            border: 1px solid var(--severity-med-border);
        }}

        .badge-low {{
            background-color: var(--severity-low-bg);
            color: var(--severity-low-text);
            border: 1px solid var(--severity-low-border);
        }}

        .service-banner {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
            background-color: #f1f5f9;
            padding: 8px 12px;
            border-radius: 8px;
            font-size: 12px;
            color: #334155;
            display: inline-block;
            max-width: 100%;
            word-break: break-all;
            margin-bottom: 8px;
        }}

        .findings-list {{
            display: flex;
            flex-direction: column;
            gap: 16px;
        }}

        .finding-card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 20px;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05);
            display: flex;
            gap: 20px;
            align-items: flex-start;
            transition: transform 0.2s, box-shadow 0.2s;
        }}

        .finding-card:hover {{
            transform: translateX(4px);
            box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.05);
        }}

        .finding-card.severity-High {{
            border-left: 6px solid var(--severity-high);
        }}

        .finding-card.severity-Medium {{
            border-left: 6px solid var(--severity-med);
        }}

        .finding-card.severity-Low {{
            border-left: 6px solid var(--severity-low);
        }}

        .finding-content {{
            flex: 1;
        }}

        .finding-title {{
            font-weight: 700;
            font-size: 16px;
            margin-bottom: 6px;
            display: flex;
            align-items: center;
            gap: 12px;
            color: #1e293b;
        }}

        .finding-desc {{
            color: #475569;
            font-size: 14px;
        }}

        .footer {{
            text-align: center;
            margin-top: 60px;
            padding-top: 20px;
            border-top: 1px solid var(--border);
            color: var(--text-muted);
            font-size: 13px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Vulnerability Scan Report</h1>
            <div class="header-meta">
                <span><strong>Target:</strong> {escaped_target}</span>
                <span><strong>Scan Time:</strong> {escaped_scan_time}</span>
            </div>
        </div>

        <div class="grid-summary">
            <div class="card-stat">
                <div class="stat-value">{len(scan_results)}</div>
                <div class="stat-label">Total Ports Scanned</div>
            </div>
            <div class="card-stat">
                <div class="stat-value" style="color: { 'var(--severity-high)' if len(open_ports) > 0 else 'var(--status-open)' };">{len(open_ports)}</div>
                <div class="stat-label">Open Ports</div>
            </div>
            <div class="card-stat">
                <div class="stat-value" style="color: { 'var(--severity-high)' if len(findings) > 0 else 'var(--text-main)' };">{len(findings)}</div>
                <div class="stat-label">Security Findings</div>
            </div>
            <div class="card-stat">
                <div class="stat-value" style="color: {overall_risk_color};">{overall_risk}</div>
                <div class="stat-label">Overall Risk Score</div>
            </div>
        </div>

        <div class="section-title">Port Details</div>
        <div class="card-table">
            <table>
                <thead>
                    <tr>
                        <th style="width: 100px;">Port</th>
                        <th style="width: 220px;">Service</th>
                        <th style="width: 120px;">Status</th>
                        <th>Scan Findings & Banners</th>
                    </tr>
                </thead>
                <tbody>
                    {"".join(port_rows_html)}
                </tbody>
            </table>
        </div>

        <div class="section-title">Security Findings Summary</div>
        <div class="findings-list">
            {"".join(findings_html)}
        </div>

        <div class="footer">
            <p>Generated by Vulnerability Scanner CLI • {escaped_scan_time}</p>
        </div>
    </div>
</body>
</html>
"""

    # Save the HTML report
    with open(html_report_path, "w", encoding="utf-8") as f:
        f.write(html_content)
        
    return txt_report_path, html_report_path
