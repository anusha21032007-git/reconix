"""
vulnerabilities.py

Provides mapping of common ports to potential security vulnerabilities and recommendations.
"""

VULNERABILITY_DB = {
    21: {
        "service": "FTP (File Transfer Protocol)",
        "description": "FTP transmits data, including credentials, in cleartext. It is vulnerable to interception (sniffing) and brute-force attacks. Anonymous login might also be enabled.",
        "recommendation": "Disable FTP and migrate to a secure alternative like SFTP (SSH File Transfer Protocol) or FTPS (FTP over SSL/TLS)."
    },
    22: {
        "service": "SSH (Secure Shell)",
        "description": "SSH is secure, but if misconfigured or running outdated versions, it can be vulnerable to brute-force attacks, credential stuffing, or exploit-based access.",
        "recommendation": "Enforce strong key-based authentication, disable root password logins, change the default port if appropriate, and use tools like fail2ban to limit login attempts."
    },
    23: {
        "service": "Telnet",
        "description": "Telnet transmits all communications, including username and passwords, in unencrypted cleartext. Any attacker on the path can easily sniff credentials.",
        "recommendation": "Disable the Telnet service immediately and use SSH (port 22) for remote command-line access."
    },
    25: {
        "service": "SMTP (Simple Mail Transfer Protocol)",
        "description": "SMTP servers can be exploited for email spoofing, spam distribution (if open relay is enabled), or user enumeration. Cleartext communication is also standard unless STARTTLS is enforced.",
        "recommendation": "Disable open relaying, require authentication, enforce TLS/STARTTLS, and configure proper SPF, DKIM, and DMARC records."
    },
    53: {
        "service": "DNS (Domain Name System)",
        "description": "Open DNS resolvers can be abused in DNS amplification DDoS attacks. Outdated DNS software may also suffer from cache poisoning or remote code execution vulnerabilities.",
        "recommendation": "Restructure access control lists to only allow queries from trusted clients, disable recursive queries for external requests, and keep DNS software updated."
    },
    80: {
        "service": "HTTP (Hypertext Transfer Protocol)",
        "description": "HTTP traffic is sent in cleartext, exposing users to session hijacking and credential theft via eavesdropping. Web applications on this port might also contain application-level security flaws (e.g. XSS, SQLi).",
        "recommendation": "Enforce HTTPS (port 443) by redirecting all traffic from port 80. Configure HTTP Strict Transport Security (HSTS) headers."
    },
    443: {
        "service": "HTTPS (HTTP Secure)",
        "description": "While HTTPS encrypts traffic, servers can be vulnerable to SSL/TLS flaws if utilizing outdated cipher suites, expired certificates, or old protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1).",
        "recommendation": "Ensure the server is configured to support only secure modern TLS protocols (TLS 1.2, TLS 1.3), disable weak ciphers, and keep SSL certificates up-to-date."
    },
    3306: {
        "service": "MySQL Database",
        "description": "Exposing database ports directly to the internet is a severe security risk. It invites constant brute-force attacks and increases the risk of unauthorized database access or exploits.",
        "recommendation": "Do not expose database ports directly to the internet. Bind MySQL to localhost (127.0.0.1) or allow access only through a secure VPN or SSH tunnel."
    }
}

def get_vulnerability_info(port: int) -> dict:
    """
    Returns vulnerability details for a given port if mapped, or a generic placeholder.
    
    Args:
        port (int): The scanned port number.
        
    Returns:
        dict: A dictionary containing 'service', 'description', and 'recommendation'.
    """
    return VULNERABILITY_DB.get(port, {
        "service": f"Unknown Service (Port {port})",
        "description": "No detailed vulnerability signature is defined for this port in this scanner.",
        "recommendation": "Verify what service is listening on this port and ensure it is properly updated and configured securely."
    })


# Rule definitions for analyzing open ports to generate security findings.
# Each key represents a port, and the value is a dictionary containing:
# - 'severity': High, Medium, Low depending on the level of risk the open port poses.
# - 'message': A clear, user-friendly description of the risk/recommendation.
PORT_RULES = {
    21: {
        "severity": "High",
        # Rule: Port 21 (FTP) - Warn that anonymous login may be enabled.
        # Explanation: FTP lacks encryption and anonymous logins can expose files to unauthorized users.
        "message": "FTP (Port 21) is open. Anonymous login may be enabled, and all credentials/data are transmitted in plaintext."
    },
    22: {
        "severity": "Medium",
        # Rule: Port 22 (SSH) - Recommend strong passwords and key-based authentication.
        # Explanation: SSH is secure, but vulnerable to brute-force attacks if weak credentials are used.
        "message": "SSH (Port 22) is open. Recommend enforcing strong passwords and key-based authentication."
    },
    23: {
        "severity": "High",
        # Rule: Port 23 (Telnet) - Warn that Telnet is insecure because data is transmitted in plaintext.
        # Explanation: Telnet sends usernames, passwords, and commands unencrypted, making it easy to sniff.
        "message": "Telnet (Port 23) is open. Telnet is insecure because data is transmitted in plaintext."
    },
    80: {
        "severity": "Medium",
        # Rule: Port 80 (HTTP) - Recommend using HTTPS where possible.
        # Explanation: Plaintext HTTP traffic is vulnerable to man-in-the-middle attacks and session hijacking.
        "message": "HTTP (Port 80) is open. Recommend using HTTPS where possible to encrypt traffic and protect user sessions."
    },
    443: {
        "severity": "Low",
        # Rule: Port 443 (HTTPS) - Mark as secure but suggest verifying TLS configuration.
        # Explanation: While HTTPS is secure, weak TLS versions or bad cipher configurations can still compromise it.
        "message": "HTTPS (Port 443) is open. Service is encrypted/secure, but suggest verifying TLS configuration (disable TLS 1.0/1.1, check certificates)."
    },
    3306: {
        "severity": "High",
        # Rule: Port 3306 (MySQL) - Warn that the database port is publicly exposed.
        # Explanation: Databases should never be directly accessible from the internet, as they are high-value targets.
        "message": "MySQL (Port 3306) is open. The database port is publicly exposed, risking brute-force attacks and unauthorized access."
    }
}


def analyze_ports(open_ports: list) -> list:
    """
    Analyzes a list of open ports and generates basic security findings.

    Args:
        open_ports (list): A list of open port numbers (integers).

    Returns:
        list: A list of dictionaries representing the security findings.
              Each dictionary contains:
              - 'port' (int): The analyzed port.
              - 'severity' (str): Severity level ('Low', 'Medium', or 'High').
              - 'message' (str): The finding warning or recommendation.
    """
    findings = []

    for port in open_ports:
        # Check if the port has a matching analysis rule defined in PORT_RULES
        if port in PORT_RULES:
            rule = PORT_RULES[port]
            findings.append({
                "port": port,
                "severity": rule["severity"],
                "message": rule["message"]
            })

    return findings


def get_overall_risk(findings: list) -> str:
    """
    Determines the overall risk score ('Low', 'Medium', 'High') based on findings.
    
    Args:
        findings (list): A list of dictionaries representing security findings.
        
    Returns:
        str: 'Low', 'Medium', or 'High' depending on the findings.
    """
    if not findings:
        return "Low"
    severities = [f["severity"].upper() for f in findings]
    if "HIGH" in severities:
        return "High"
    if "MEDIUM" in severities:
        return "Medium"
    return "Low"



