"""
scanner.py

A Python-based CLI Vulnerability Scanner that checks common ports,
performs banner grabbing, identifies vulnerabilities, and generates reports.
"""

import sys
import os
import socket
import ipaddress
import re
from report import save_report
from vulnerabilities import analyze_ports

# Initialize Windows Terminal ANSI Escape Sequence support if running on Windows
if os.name == 'nt':
    os.system('')

# ANSI escape codes for styling the CLI output
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[91m"      # HIGH severity / Warning
GREEN = "\033[92m"    # OPEN status / Safe
YELLOW = "\033[93m"   # MEDIUM severity / Recommendation
BLUE = "\033[94m"     # INFO / CLOSED / LOW severity
CYAN = "\033[96m"     # Header / Title / ASCII Banner

# Common ports requested to be scanned
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 443, 3306]

def print_banner():
    """
    Prints a professional ASCII banner for the scanner tool.
    """
    banner = f"""{CYAN}{BOLD}
 ============================================================
   _____ _     _             _                            
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██║ ╚███╔╝
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║ ██╔██╗
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝
       
                                                           
                 VULNERABILITY SCANNER v2.0
 ============================================================
{RESET}"""
    print(banner)

def print_summary_table(scan_results: dict, banners: dict):
    """
    Prints a formatted, color-coded summary table of all scanned ports.
    """
    print(f"\n{BOLD}{CYAN}+" + "-"*6 + "+" + "-"*30 + "+" + "-"*10 + "+" + "-"*18 + "+")
    print(f"| {'Port':<4} | {'Service':<28} | {'Status':<8} | {'Severity Finding':<16} |")
    print("+" + "-"*6 + "+" + "-"*30 + "+" + "-"*10 + "+" + "-"*18 + f"+{RESET}")
    
    from vulnerabilities import get_vulnerability_info
    
    # Analyze open ports to map finding severities
    open_ports = [port for port, status in scan_results.items() if status == "OPEN"]
    findings = analyze_ports(open_ports)
    findings_map = {f["port"]: f["severity"] for f in findings}
    
    for port in sorted(scan_results.keys()):
        status = scan_results[port]
        vuln_info = get_vulnerability_info(port)
        service = vuln_info["service"]
        
        # Limit service name length for display inside the table
        if len(service) > 28:
            service = service[:25] + "..."
            
        severity = findings_map.get(port, "None")
        
        # Format columns manually using pre-defined widths and exact spaces
        # to ensure the table borders align correctly when using ANSI color codes.
        if status == "OPEN":
            status_cell = f"{GREEN}OPEN{RESET}    "
        else:
            status_cell = f"{BLUE}CLOSED{RESET}  "
            
        if severity == "High":
            severity_cell = f"{RED}HIGH{RESET}            "
        elif severity == "Medium":
            severity_cell = f"{YELLOW}MEDIUM{RESET}          "
        elif severity == "Low":
            severity_cell = f"{BLUE}LOW{RESET}             "
        else:
            severity_cell = "None            "
            
        print(f"| {port:<4} | {service:<28} | {status_cell} | {severity_cell} |")
        
    print(f"{BOLD}{CYAN}+" + "-"*6 + "+" + "-"*30 + "+" + "-"*10 + "+" + "-"*18 + f"+{RESET}\n")

def validate_target(target: str) -> bool:
    """
    Validates if the target string is a syntactically valid IP address or hostname.
    This prevents injection of command characters or path traversal elements.
    
    Args:
        target (str): Hostname or IP input.
        
    Returns:
        bool: True if valid, False otherwise.
    """
    if not target or len(target.strip()) == 0:
        return False
        
    target = target.strip()
    
    # 1. Check if it's a valid IPv4 or IPv6 address
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
        
    # 2. Check if it is a valid hostname format (RFC 1123 constraints)
    if len(target) > 253:
        return False
        
    # Regular expression for hostname check (alphanumeric, dots, hyphens only)
    hostname_regex = re.compile(
        r'^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])'
        r'(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$'
    )
    return bool(hostname_regex.match(target))

def grab_banner(target_ip: str, port: int) -> str:
    """
    Attempts to connect and grab the service banner from an open port.
    
    Args:
        target_ip (str): IP address of the target.
        port (int): Open port number.
        
    Returns:
        str: Service banner if retrieved, empty string otherwise.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)  # Set a short timeout for banner collection
    banner = ""
    try:
        s.connect((target_ip, port))
        
        # If it's a web port (80 or 443), send a basic HTTP request to get headers
        if port in [80, 443]:
            s.sendall(b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            response = s.recv(1024).decode('utf-8', errors='ignore')
            # Extract Server header if present
            for line in response.split("\r\n"):
                if line.lower().startswith("server:"):
                    banner = line
                    break
            if not banner and response:
                banner = response.split("\r\n")[0]  # Fallback to status line
        else:
            # FTP, SSH, SMTP, etc. automatically send greeting banners upon connection
            banner = s.recv(1024).decode('utf-8', errors='ignore')
    except socket.error:
        pass
    finally:
        s.close()
    return banner.strip()

def scan_target(target: str, ports: list) -> list:
    """
    Scans the target host for a list of ports using Python's socket library.
    Displays dynamic scanning progress and colored console outputs.
    
    Args:
        target (str): Hostname or IP to scan.
        ports (list): List of port numbers to scan.
        
    Returns:
        list: List of open ports.
    """
    # Resolve host to IP first to ensure DNS check passes
    try:
        target_ip = socket.gethostbyname(target)
        print(f"\n{GREEN}[+] Resolved '{target}' to IP: {target_ip}{RESET}")
    except socket.gaierror:
        print(f"\n{RED}[-] Error: Could not resolve target host '{target}'{RESET}")
        return []

    print(f"{GREEN}[+] Starting scan on target: {target_ip}{RESET}")
    print(f"{GREEN}[+] Scanning ports: {', '.join(map(str, ports))}{RESET}\n")
    
    open_ports = []
    scan_results = {}
    banners = {}
    
    total_ports = len(ports)
    for index, port in enumerate(ports, start=1):
        # 1. Update and print dynamic progress bar on the terminal
        percent = int((index / total_ports) * 100)
        bar_length = 20
        filled_length = int(bar_length * index // total_ports)
        bar = "█" * filled_length + "-" * (bar_length - filled_length)
        print(f"\r{CYAN}[*] Progress: [{bar}] {percent}% (Scanning port {port}...){RESET}", end="", flush=True)
        
        # Create standard TCP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.5)  # Set connection timeout to 1.5 seconds
        
        try:
            # Try connecting
            result = s.connect_ex((target_ip, port))
            
            # Clear the progress bar line before printing final port status
            print("\r\033[K", end="")
            
            if result == 0:
                print(f"{GREEN}[+] Port {port:<5} : OPEN{RESET}")
                scan_results[port] = "OPEN"
                open_ports.append(port)
                
                # Perform banner grabbing
                banner = grab_banner(target_ip, port)
                if banner:
                    banners[port] = banner
                    # Limit displayed banner length to avoid messiness
                    display_banner = banner.replace('\r', '').replace('\n', ' ')
                    if len(display_banner) > 50:
                        display_banner = display_banner[:47] + "..."
                    print(f"        {YELLOW}-> Service Banner: {display_banner}{RESET}")
            else:
                print(f"{BLUE}[-] Port {port:<5} : CLOSED{RESET}")
                scan_results[port] = "CLOSED"
        except socket.error as e:
            print("\r\033[K", end="")
            print(f"{BLUE}[-] Port {port:<5} : CLOSED (Error: {e}){RESET}")
            scan_results[port] = "CLOSED"
        finally:
            s.close()
            
    print(f"\n{GREEN}[+] Scan finished. Found {len(open_ports)} open port(s).{RESET}")
    
    # 2. Print a clean, formatted ASCII summary table
    print_summary_table(scan_results, banners)
    
    # Run security analysis on open ports and display summary
    findings = analyze_ports(open_ports)
    
    # 3. Calculate target overall risk score based on findings
    severities = [f["severity"] for f in findings]
    if "High" in severities:
        overall_risk = "High"
        risk_color = RED
    elif "Medium" in severities:
        overall_risk = "Medium"
        risk_color = YELLOW
    elif "Low" in severities:
        overall_risk = "Low"
        risk_color = BLUE
    else:
        overall_risk = "Safe"
        risk_color = GREEN
        
    print(f"{BOLD}Overall Target Risk Score: {risk_color}{overall_risk.upper()}{RESET}")
    
    if findings:
        print(f"\n{BOLD}{RED}============================================================{RESET}")
        print(f"                  {BOLD}{RED}SECURITY FINDINGS SUMMARY{RESET}")
        print(f"{BOLD}{RED}============================================================{RESET}")
        for finding in findings:
            # Match severity color
            if finding["severity"] == "High":
                sev_color = RED
            elif finding["severity"] == "Medium":
                sev_color = YELLOW
            else:
                sev_color = BLUE
                
            print(f"[{sev_color}{finding['severity'].upper()}{RESET}] Port {finding['port']}: {finding['message']}")
        print(f"{BOLD}{RED}============================================================{RESET}\n")
        
    # Generate and save reports (Text and HTML)
    if open_ports or scan_results:
        print(f"{CYAN}[*] Generating reports...{RESET}")
        txt_path, html_path = save_report(target, scan_results, banners)
        print(f"{GREEN}[+] Text report successfully saved to:\n    {txt_path}{RESET}")
        print(f"{GREEN}[+] HTML report successfully saved to:\n    {html_path}{RESET}")
        
    return open_ports

def run_scan():
    """
    Executes a single scanning session. Prompts for target, validates input,
    and runs the port scan.
    """
    while True:
        target = input("Enter target IP address or hostname to scan: ").strip()
        if not target:
            continue
        if validate_target(target):
            scan_target(target, COMMON_PORTS)
            break
        else:
            print(f"\n{RED}[-] Error: Invalid IP address or hostname syntax.{RESET}")
            print("-" * 60)

def main():
    print_banner()
    
    print(f"{BOLD}This utility scans common ports using standard sockets, grabs banners,")
    print(f"and provides security recommendations for open services.{RESET}")
    print("-" * 60)
    
    try:
        while True:
            run_scan()
            
            # Prompt user to check if they want to scan another host
            while True:
                choice = input("\nDo you want to scan another host? (y/n): ").strip().lower()
                if choice in ['y', 'yes']:
                    print("-" * 60)
                    break
                elif choice in ['n', 'no']:
                    print(f"\n{GREEN}Thank you for using the Vulnerability Scanner!{RESET}")
                    sys.exit(0)
                else:
                    # Re-prompt on invalid choices
                    pass
    except KeyboardInterrupt:
        print(f"\n{RED}[-] Scan cancelled by user.{RESET}")
        sys.exit(0)

if __name__ == "__main__":
    main()