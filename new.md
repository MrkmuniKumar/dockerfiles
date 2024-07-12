
-------------------------------------------------------------------------------------------------------------------------------------------
**Set 1**

1. **Hands-on (RBAC & NIST):** Design a Role-Based Access Control (RBAC) model for a three-tier e-commerce application using the NIST Special Publication 800-30 framework. Identify user roles, permissions, and access levels for each tier.
2. **Situation-based (Security):** You identify suspicious activity on your company's web server logs. Describe the steps you would take to investigate the potential security threat.
3. **Theoretical (COBIT):** Explain the five principles of COBIT for IT governance and their importance in managing an IT organization.
4. **Hands-on (Automation):** Write a script (pseudocode or specific language) to automate the deployment of a new web application to a development server environment.
5. **Threat Modeling:** Describe the STRIDE threat modeling methodology and its benefits for identifying potential security threats in a system.

## Set 1: Answers and Evaluation Criteria

**1. Hands-on (RBAC & NIST):**

**Expected Answer:**

Here's a sample RBAC model for a three-tier e-commerce application using the NIST SP 800-30 framework:

**Roles:**

* **Customer:** Can browse products, add items to cart, view order history (read-only access to presentation and application tiers).
* **Sales Associate:** Can process customer orders, manage product inventory (read/write access to presentation and application tiers, limited access to data storage for order details).
* **Administrator:** Can manage user accounts, configure system settings, access all data for auditing purposes (full access to all tiers).

**Permissions & Access Levels:**

| Tier | Role | Permissions |
|---|---|---|
| Presentation | Customer, Sales Associate, Administrator | Read |
| Application | Customer (limited), Sales Associate, Administrator | Read/Write (limited for Customer) |
| Data Storage | Sales Associate (limited), Administrator | Read/Write (limited for Sales Associate) |

**Evaluation Criteria:**

* Clearly identifies user roles relevant to an e-commerce application.
* Defines appropriate permissions (read, write, execute) for each role at each tier.
* Demonstrates an understanding of the NIST SP 800-30 framework for access control.

**2. Situation-based (Security):**

**Expected Answer:**

1. **Identify the Suspicious Activity:** Analyze the web server logs for specific details like:
    * Unusual access times (outside of regular business hours)
    * Failed login attempts (repeated attempts from a single IP address)
    * Download activity of sensitive files
    * Access attempts from unexpected locations

2. **Initial Response:**
    * Isolate the suspicious IP address by temporarily blocking access.
    * Secure the server by changing passwords and reviewing security configurations.

3. **Investigation:**
    * Analyze log data further to identify the source and nature of the threat.
    * Use security tools to scan for malware or vulnerabilities on the server.

4. **Reporting and Remediation:**
    * Report the incident to the security team and relevant authorities.
    * Implement appropriate remediation actions based on the investigation findings.

**Evaluation Criteria:**

* Demonstrates a systematic approach to investigating suspicious activity.
* Identifies key details to analyze in web server logs.
* Describes appropriate initial response actions to mitigate the threat.


**3. Theoretical (COBIT):**

**Expected Answer:**

COBIT 5 outlines five key principles for IT governance:

1. **Plan & Organize:**  Defines a strategic plan for IT resources, aligning with business goals.
2. **Build & Acquire:**  Ensures the acquisition and development of IT resources meet business needs.
3. **Deliver & Support:** Focuses on delivering and supporting IT services effectively and efficiently.
4. **Monitor & Evaluate:**  Tracks performance of IT processes and services against established metrics.
5. **Optimize:** Continuously improves IT processes and services based on monitoring and evaluation.

**Importance of COBIT principles:**

* COBIT provides a structured framework for managing IT effectively.
* It promotes alignment between business objectives and IT investments.
* It helps ensure efficient service delivery and resource utilization.
* It emphasizes continuous improvement and adaptation within the IT organization.

**Evaluation Criteria:**

* Accurately defines the five COBIT principles.
* Explains the importance of each principle for IT governance.
* Demonstrates an understanding of the benefits of COBIT for managing IT resources.

**4. Hands-on (Automation):**

**Expected Answer:** (This answer will depend on the chosen scripting language)

**Example (Python Script):**

```python
def deploy_web_app(app_name, server_ip):
  # Copy application files to server
  # Configure server settings (e.g., database connection)
  # Restart relevant services (e.g., web server)

# Example usage
deploy_web_app("myapp", "192.168.1.10")
```

**Evaluation Criteria:**

* Script demonstrates automation of web application deployment steps.
* Script utilizes appropriate functions for file transfer, configuration, and service restart.
* The chosen language syntax is correct and well-formatted.

**5. Threat Modeling:**

**Expected Answer:**

STRIDE is a threat modeling methodology used to identify potential security threats in a system. It focuses on six categories:

* **Spoofing:** Impersonating a legitimate user or system.
* **Tampering:** Modifying data or system configurations.
* **Repudiation:** Denying involvement in an action.
* **Information Disclosure:** Unauthorized access to confidential information.
* **Denial of Service (DoS):** Disrupting normal system
-------------------------------------------------------------------------------------------------------------------------------------------

**Set 2**

1. **Hands-on (DevOps & Security):**  Using a DevOps pipeline diagram, illustrate the integration of security testing throughout the software development lifecycle (SDLC). 
2. **Situation-based (ITIL):** Your company's service desk experiences a surge in incident tickets due to a recent software update.  How would you utilize the ITIL incident management process to resolve these incidents efficiently?
3. **Theoretical (CISM):** Explain the concept of information security governance and its key components according to the CISM framework.
4. **Hands-on (Security Scripting):** Write a basic script (pseudocode or specific language) to scan a list of IP addresses for open ports using a common vulnerability scanner tool.
5. **NIST:** Briefly describe the NIST Cybersecurity Framework (CSF) core functions and their role in managing cybersecurity risk.

## Set 2: Answers and Evaluation Criteria

**1. Hands-on (DevOps & Security):**

**Expected Answer:**

* Create a DevOps pipeline diagram with stages representing the SDLC phases (e.g., Code Commit, Build, Test, Deploy).
* Integrate security testing activities within each stage:
    * **Code Commit:** Use static code analysis tools to identify potential vulnerabilities in code during commit.
    * **Build:** Automate security scans during the build process to detect vulnerabilities in compiled code or libraries.
    * **Test:** Include security testing tools like dynamic application security testing (DAST) and penetration testing as part of the testing process.
    * **Deploy:** Implement vulnerability scanning and security configuration checks before deploying the application to production.

**Evaluation Criteria:**

* The diagram clearly depicts the SDLC stages and DevOps pipeline flow.
* Security testing activities are strategically placed within each relevant stage.
* The explanation demonstrates an understanding of how security is integrated throughout the development lifecycle.

**2. Situation-based (ITIL):**

**Expected Answer:**

Utilize the ITIL incident management process to address the surge in incident tickets:

* **Identification:** Categorize the incidents related to the software update (e.g., installation failure, functional issues).
* **Logging & Classification:** Log all incidents with details like user reports, symptoms, and timestamps. Classify them based on severity and impact.
* **Prioritization:** Prioritize incidents based on urgency and potential business disruption.
* **Ownership & Assignment:** Assign incidents to qualified support personnel for troubleshooting.
* **Resolution & Recovery:** Implement solutions to resolve the incidents and restore normal operations. 
* **Closure:** Document the resolution process, lessons learned, and updates for future reference.
* **Communication:** Communicate with affected users throughout the incident management process, keeping them informed about the status and resolution steps.

**Evaluation Criteria:**

* Accurately describes the key steps in the ITIL incident management process.
* Demonstrates a logical approach to handling a surge in incident tickets related to a software update.
* Emphasizes the importance of communication and documentation during incident resolution.

**3. Theoretical (CISM):**

**Expected Answer:**

Information security governance (ISG) is the framework that ensures an organization's information assets are adequately protected. CISM defines five key components of ISG:

* **Strategy & Management:** Aligning security strategy with business objectives, establishing security policies.
* **Risk Management:** Identifying, analyzing, and mitigating information security risks.
* **Information Security Architecture & Design:**  Designing secure systems and infrastructure to protect information.
* **Implementation & Operation:** Implementing security controls, managing security incidents.
* **Measurement & Evaluation:** Monitoring security effectiveness, measuring security performance.

**Evaluation Criteria:**

* Provides a clear definition of information security governance.
* Accurately identifies the five key components of ISG according to the CISM framework.
* Explains the significance of each component in achieving effective information security.

**4. Hands-on (Security Scripting):**

**Example (Python Script using Nmap):**

```python
import nmap

scanner = nmap.PortScanner()

def scan_ports(ip_list):
  for ip in ip_list:
    response = scanner.scan(ip, arguments='-sT -Pn')  # TCP SYN scan, no banners 
    if response['scan'][ip]['status']['state'] == 'up':
      print(f"IP: {ip} - Open Ports: {', '.join(response['scan'][ip]['tcp'].keys())}")

# Example usage
ip_list = ["192.168.1.1", "10.0.0.1"]
scan_ports(ip_list)
```

**Evaluation Criteria:**

* The script utilizes a vulnerability scanner library (e.g., Nmap) for scanning purposes.
* The script scans a list of IP addresses for open ports.
* The script outputs information about identified open ports on each scanned IP.

**5. NIST:**

**Expected Answer:**

The NIST Cybersecurity Framework (CSF) defines five core functions to manage cybersecurity risk:

* **Identify:** Identify and prioritize assets, threats, and vulnerabilities within the organization.
* **Protect:** Implement security controls to protect assets from identified threats and vulnerabilities.
* **Detect:** Employ detection methods to identify and report security incidents in a timely manner.
* **Respond:** Contain, eradicate, and recover from security incidents effectively.
* **Recover:** Restore functionality of systems and data after a security incident.

**Evaluation Criteria:**

* Accurately describes the five core functions of the NIST Cybersecurity Framework.
* Explains the role of each function in managing cybersecurity risk.
* Demonstrates an understanding of the comprehensive approach advocated by the
-------------------------------------------------------------------------------------------------------------------------------------------

**Set 3**

1. **Hands-on (Web Security Scripting):** Write a script (pseudocode or specific language) to automate the process of scanning a website for common vulnerabilities like SQL injection and cross-site scripting (XSS) using a publicly available web vulnerability scanner library. 
2. **Situation-based (Network Security):** You suspect a network intrusion on your company network. Describe the steps you would take to identify the source of the attack and isolate the compromised device.
3. **Theoretical (Secure Coding):** Explain the OWASP Top 10 web application security risks and how secure coding practices can mitigate these vulnerabilities.
4. **Hands-on (Security Policy Update):**  Review your existing password policy and propose updates to strengthen password complexity requirements and enforce multi-factor authentication (MFA).
5. **Cloud Security:** Discuss the concept of cloud security posture management (CSPM) and its benefits for maintaining a secure cloud environment.

**Set 4**

1. **Hands-on (Password Hashing):**  Write a script (pseudocode or specific language) to demonstrate how password hashing works. The script should take a plain-text password as input and generate a secure hash using a common hashing algorithm (e.g., SHA-256).
2. **Situation-based (Incident Response & Forensics):** A ransomware attack encrypts critical company data. Describe the initial steps you would take to isolate the attack and begin the incident response and forensic analysis process.
3. **Theoretical (Security Monitoring):** Explain the difference between Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS) and their roles in network security monitoring.
4. **Hands-on (Security Logging):**  Write a script (pseudocode or specific language) to parse system logs and identify potential suspicious activity based on predefined log entries.
5. **Container Security:** Discuss best practices for securing container registries, including access control and vulnerability scanning.

**Set 5**

1. **Hands-on (Security Tool):**  Explore a vulnerability scanner tool like Nessus or OpenVAS. Write steps on how to use the tool to scan a system for vulnerabilities and generate a report.
2. **Situation-based (Physical Security):** A server room access badge is lost. Explain the steps you would take to secure the server room and prevent unauthorized access.
3. **Theoretical (Penetration Testing):** Briefly explain the different phases of a penetration testing methodology and the ethical considerations involved.
4. **Hands-on (Security Awareness Training):** Develop a short security awareness training module for employees on best practices for identifying and avoiding phishing attacks.
5. **Cloud Security:** Discuss the concept of Infrastructure as Code (IaC) and its security implications for managing cloud resources. 
