
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

## Set 3: Answers and Evaluation Criteria

**1. Hands-on (Web Security Scripting):**

**Expected Answer:**

**Example (Python Script using Requests and a Scanner Library):**

```python
import requests
from vulnerability_scanner import scan_for_vulnerabilities  # Replace with your chosen library

def scan_website(url):
  response = requests.get(url)
  vulnerability_report = scan_for_vulnerabilities(response.text, url)  # Scanner library function call
  if vulnerability_report:
    print(f"Potential vulnerabilities found on {url}:")
    for vulnerability in vulnerability_report:
      print(f"\t- {vulnerability['type']}: {vulnerability['details']}")
  else:
    print(f"No vulnerabilities detected on {url}.")

# Example usage
website_url = "https://www.example.com"
scan_website(website_url)
```

**Note:** Replace `vulnerability_scanner` with the actual library name (e.g., WAFW00L [NOT RECOMMENDED FOR PRODUCTION USE DUE TO LEGAL RESTRICTIONS], WPScan). These libraries often have specific usage instructions, so consult their documentation.

**Evaluation Criteria:**

* The script utilizes a web vulnerability scanner library to analyze the website content.
* The script automates the scanning process for a given website URL.
* The script parses the scanner output and reports potential vulnerabilities with details (type and description).

**2. Situation-based (Network Security):**

**Expected Answer:**

1. **Identify Suspicious Activity:** Analyze network traffic logs for anomalies like:
    * Unusual traffic patterns (increased bandwidth usage, unexpected source/destination IPs)
    * Failed login attempts from unknown locations
    * Access attempts to critical resources

2. **Isolate the Compromised Device:**
    * Use network traffic analysis tools to identify the compromised device's IP address.
    * Quarantine the infected device by blocking its network access from other devices.

3. **Investigation:**
    * Analyze system logs on the compromised device for signs of intrusion (unusual processes, unauthorized access attempts).
    * Utilize forensic tools to identify the nature of the attack and any compromised data.

4. **Containment & Recovery:**
    * Patch vulnerabilities on the compromised device and other potentially vulnerable systems.
    * Implement additional security controls to prevent future attacks.
    * Restore affected systems from backups if necessary.

**Evaluation Criteria:**

* Demonstrates a systematic approach to identifying a network intrusion.
* Describes steps to isolate the compromised device and prevent further damage.
* Emphasizes the importance of investigating the root cause and implementing recovery measures.

**3. Theoretical (Secure Coding):**

**Expected Answer:**

The OWASP Top 10 web application security risks are a list of the most prevalent threats faced by web applications. Secure coding practices can mitigate these vulnerabilities:

* **Injection:** (SQLi, XSS) - Validate and sanitize user input to prevent malicious code injection.
* **Broken Authentication:** Implement strong password hashing, enforce session management best practices.
* **Sensitive Data Exposure:** Encrypt sensitive data at rest and in transit, restrict access based on the principle of least privilege.
* **Security Misconfigurations:** Follow secure coding principles and guidelines for specific programming languages and frameworks.
* **Broken Session Management:** Utilize secure session tokens with expiration times, prevent session hijacking techniques.
* **Insecure Direct Object References:** Validate and sanitize user input to prevent unauthorized access to sensitive resources.
* **Security Misconfiguration:** Follow secure server configuration guidelines, keep software and libraries updated.
* **Cross-Site Scripting (XSS):** Escape user input before displaying it on the web page to prevent script injection.
* **Insecure Deserialization:** Implement secure deserialization libraries that validate and sanitize untrusted data.
* **Using Components with Known Vulnerabilities:** Keep libraries and frameworks updated to address known vulnerabilities.

**Evaluation Criteria:**

* Accurately identifies the OWASP Top 10 web application security risks.
* Explains how secure coding practices can mitigate each vulnerability type.
* Demonstrates an understanding of the importance of secure coding for web application security.

**4. Hands-on (Security Policy Update):**

**Expected Answer:**

**Review Existing Password Policy:**

* Minimum password length requirement (should be at least 12 characters)
* Complexity requirements (uppercase, lowercase, numbers, special characters)
* Password history (prevent reuse of recent passwords)

**Proposed Updates:**

* Increase minimum password length requirement.
* Enforce stronger complexity requirements (e.g., minimum number of character types).
* Implement mandatory password rotation (e.g., every 3 months).
* Enforce Multi-factor Authentication (MFA) for all user accounts.


**5. Cloud Security:**

**Expected Answer:**

Cloud Security Posture Management (CSPM) is a process and technology that helps organizations continuously monitor and manage the security posture of their cloud environments. It provides visibility into security risks, misconfigurations, and potential compliance issues across cloud resources (IaaS, PaaS, SaaS).

**Benefits of CSPM:**

* **Improved Security Visibility:**  Provides a centralized view of security posture across the entire cloud environment.
* **Proactive Threat Detection:**  Identifies potential security risks and misconfigurations before they can be exploited.
* **Enhanced Compliance Management:**  Helps organizations meet regulatory compliance requirements for cloud security. 
* **Streamlined Security Operations:** Automates security tasks and simplifies security management in the cloud.
* **Reduced Security Costs:**  Proactive identification and mitigation of security issues helps avoid costly breaches.

**Evaluation Criteria:**

* Accurately defines the concept of Cloud Security Posture Management (CSPM).
* Explains the key benefits of CSPM for maintaining a secure cloud environment.
* Demonstrates an understanding of how CSPM helps organizations manage security risks and compliance in the cloud.


--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


**Set 4**

1. **Hands-on (Password Hashing):**  Write a script (pseudocode or specific language) to demonstrate how password hashing works. The script should take a plain-text password as input and generate a secure hash using a common hashing algorithm (e.g., SHA-256).
2. **Situation-based (Incident Response & Forensics):** A ransomware attack encrypts critical company data. Describe the initial steps you would take to isolate the attack and begin the incident response and forensic analysis process.
3. **Theoretical (Security Monitoring):** Explain the difference between Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS) and their roles in network security monitoring.
4. **Hands-on (Security Logging):**  Write a script (pseudocode or specific language) to parse system logs and identify potential suspicious activity based on predefined log entries.
5. **Container Security:** Discuss best practices for securing container registries, including access control and vulnerability scanning.

## Set 4: Answers and Evaluation Criteria

**1. Hands-on (Password Hashing):**

**Expected Answer:**

**(Example Script - Python)**

```python
import hashlib

def hash_password(password):
  """Hashes a plain-text password using SHA-256."""
  # Encode password as bytes
  encoded_password = password.encode()
  # Generate hash using SHA-256 algorithm
  hashed_password = hashlib.sha256(encoded_password).hexdigest()
  return hashed_password

# Example usage
plain_text_password = "your_password"
hashed_password = hash_password(plain_text_password)
print(f"Hashed password: {hashed_password}")
```

**Evaluation Criteria:**

* The script defines a function to hash a password using a secure hashing algorithm (e.g., SHA-256).
* The script takes plain-text password as input and returns the generated hash.
* The script demonstrates the one-way nature of hashing (cannot retrieve original password from the hash).

**2. Situation-based (Incident Response & Forensics):**

**Expected Answer:**

**(Initial Steps)**

1. **Contain the Threat:**
    * Isolate the infected systems by disconnecting them from the network.
    * Identify and stop any ongoing ransomware encryption processes.

2. **Assess the Situation:**
    * Determine the extent of the attack (affected systems, data encrypted).
    * Identify the type of ransomware and its potential impact.

3. **Secure Evidence:**
    * Make backups of unencrypted data for potential recovery.
    * Preserve system logs and other forensic evidence for investigation.

4. **Communication & Decision Making:**
    * Notify relevant stakeholders (IT team, management, legal) about the incident.
    * Evaluate options for recovery (backups, decryption tools, negotiation).

5. **Incident Response & Forensics:**
    * Initiate a formal incident response plan to investigate the attack and recover systems.
    * Conduct forensic analysis to determine the attack origin and timeline.

**Evaluation Criteria:**

* Demonstrates a systematic approach to isolating and containing a ransomware attack.
* Identifies key steps for assessing the situation and securing evidence for forensic analysis.
* Emphasizes the importance of communication and decision-making during an incident response.

**3. Theoretical (Security Monitoring):**

**Expected Answer:**

* **Intrusion Detection System (IDS):** Monitors network traffic and system activity for suspicious behavior that might indicate an attack attempt. 
    * IDS analyzes events based on predefined signatures or anomalies and generates alerts.
    * It provides visibility into potential threats but doesn't actively block attacks.

* **Intrusion Prevention System (IPS):** Continuously monitors network traffic and enforces security policies.  
    * IPS can analyze packets and block suspicious traffic based on predefined rules or attack signatures.
    * It actively prevents attacks from reaching critical systems in real-time.

**Evaluation Criteria:**

* Accurately differentiates between Intrusion Detection Systems (IDS) and Intrusion Prevention Systems (IPS).
* Explains the role of each system in network security monitoring.
* Highlights the key difference between detection and prevention capabilities of IDS and IPS.

**4. Hands-on (Security Logging):**

**(Example Script - Python)**

```python
def parse_system_logs(log_file):
  """Parses system logs and identifies suspicious activity."""
  suspicious_entries = []
  with open(log_file, 'r') as f:
    for line in f:
      if "failed login" in line or "unusual access" in line:
        suspicious_entries.append(line)
  return suspicious_entries

# Example usage
log_file = "/var/log/auth.log"
suspicious_logs = parse_system_logs(log_file)

if suspicious_logs:
  print("Following log entries indicate potential suspicious activity:")
  for entry in suspicious_logs:
    print(entry)
else:
  print("No suspicious activity identified in the log file.")
```

**Evaluation Criteria:**

* The script parses system log entries based on predefined keywords for suspicious activity.
* The script identifies log entries that might indicate potential security incidents.
* It demonstrates basic log analysis capabilities to detect anomalies.


**5. Container Security:**

**Best Practices for Securing Container Images and Registries:**

* **Access Control:**
    * Implement strong access control mechanisms to restrict access to the registry.
    * Utilize role-based access control (RBAC) to grant appropriate permissions for different users (e.g., read-only access for developers, push access for authorized builders).
    * Use multi-factor authentication (MFA) for added security when accessing the registry.

* **Vulnerability Scanning:**
    * Integrate vulnerability scanners into the CI/CD pipeline to scan container images for known vulnerabilities before pushing them to the registry.
    * Regularly scan container images stored in the registry to identify and address potential vulnerabilities.
    * Utilize vulnerability databases like National Vulnerability Database (NVD) to stay updated about security threats.

* **Image Signing:**
    * Implement image signing using cryptographic signatures to ensure image integrity and authenticity.
    * This helps verify that the image hasn't been tampered with during storage or transfer.
    * Use a trusted signing key and restrict access to the signing process.

* **Minimize Image Size:**
    * Build container images with minimal dependencies and libraries to reduce the attack surface.
    * Smaller images are easier to scan for vulnerabilities and manage.

* **Use Official Base Images:**
    * Whenever possible, utilize official base images from trusted sources like container image repositories (e.g., Docker Hub).
    * Official images are typically well-maintained and less likely to contain vulnerabilities.

* **Keep Software Updated:**
    * Regularly update the operating system and application packages within container images to address security patches.
    * This helps mitigate vulnerabilities discovered after the image build.

* **Monitor Registry Activity:**
    * Monitor registry activity for suspicious actions like unauthorized access attempts or unusual download patterns.
    * Utilize log analysis tools to detect potential security incidents.

**Benefits of Implementing These Practices:**

* Reduces the risk of deploying vulnerable container images to production environments.
* Enhances the overall security posture of containerized applications.
* Promotes secure development practices for containerized workloads.

**Evaluation Criteria:**

* Identifies key best practices for securing container registries.
* Explains the importance of access control, vulnerability scanning, and image signing.
* Demonstrates an understanding of how these practices contribute to container security.
    
 --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------  

**Set 5**

1. **Hands-on (Security Tool):**  Explore a vulnerability scanner tool like Nessus or OpenVAS. Write steps on how to use the tool to scan a system for vulnerabilities and generate a report.
2. **Situation-based (Physical Security):** A server room access badge is lost. Explain the steps you would take to secure the server room and prevent unauthorized access.
3. **Theoretical (Penetration Testing):** Briefly explain the different phases of a penetration testing methodology and the ethical considerations involved.
4. **Hands-on (Security Awareness Training):** Develop a short security awareness training module for employees on best practices for identifying and avoiding phishing attacks.
5. **Cloud Security:** Discuss the concept of Infrastructure as Code (IaC) and its security implications for managing cloud resources.

## Set 5: Answers and Evaluation Criteria

**1. Hands-on (Security Tool):**

**Exploring Vulnerability Scanners:**

Here's a general approach using Nessus (remember specific steps might vary depending on the tool):

* **Download and Install:** Download and install Nessus from the official Tenable website (commercial) or OpenVAS (open-source) following their installation guides.
* **Configure Targets:** Define the target system or network segment you want to scan. Nessus offers options like hostname, IP address, or importing a file with target lists.
* **Select Scan Policies:** Choose a pre-defined scan policy or create a custom one to specify the types of vulnerabilities to scan for (e.g., basic network scans, detailed configuration audits).
* **Launch the Scan:** Initiate the scan and monitor its progress within the scanner interface.
* **Analyze Results:** Once the scan finishes, review the generated report. It typically includes identified vulnerabilities, severity levels, potential impact, and remediation guidance.

**Evaluation Criteria:**

* Demonstrates an understanding of using a vulnerability scanner like Nessus or OpenVAS.
* Explains the key steps involved in configuring and launching a vulnerability scan.
* Highlights the importance of analyzing scan reports to identify and address vulnerabilities.

**2. Situation-based (Physical Security):**

**Lost Server Room Access Badge:**

* **Immediate Actions:**
    * Deactivate the lost access badge to prevent unauthorized entry.
    * Increase security personnel presence around the server room to monitor access attempts.
    * If possible, change the server room door locks to require a new access key immediately.
* **Long-Term Measures:**
    * Issue new access badges to all authorized personnel.
    * Implement two-factor authentication for server room access (badge + PIN/biometric).
    * Review access logs to identify any suspicious activity around the time the badge was lost.
    * Consider implementing video surveillance around the server room entrance.

**Evaluation Criteria:**

* Identifies a logical sequence of steps to secure the server room after a lost access badge.
* Emphasizes the importance of immediate actions and long-term solutions to prevent unauthorized access.
* Demonstrates an understanding of layered security principles for physical access control.

**3. Theoretical (Penetration Testing):**

**Phases of Penetration Testing Methodology:**

* **Reconnaissance:** Gathering information about the target system (operating system, network topology, applications).
* **Enumeration:** Identifying vulnerabilities in the target system (open ports, services, misconfigurations).
* **Exploitation:** Attempting to exploit identified vulnerabilities to gain unauthorized access or control.
* **Post-Exploitation:** Maintaining access to the system, escalating privileges, and exploring further vulnerabilities.
* **Reporting:** Documenting the findings, including identified vulnerabilities, exploitation techniques, and recommendations for remediation.

**Ethical Considerations:**

* **Authorization:** Penetration testing must be authorized by the owner of the target system.
* **Scope definition:** Clearly defined scope outlines the authorized testing activities.
* **Data confidentiality:** Testers must maintain confidentiality of any sensitive data accessed during the test.
* **Reporting:** Test results should be reported to authorized personnel and addressed promptly.

**Evaluation Criteria:**

* Accurately defines the different phases of a penetration testing methodology.
* Explains the key ethical considerations that testers must adhere to during penetration testing.
* Demonstrates an understanding of responsible and ethical penetration testing practices.

**4. Hands-on (Security Awareness Training):**

**Phishing Awareness Training Module:**

**Introduction:** Briefly explain the concept of phishing attacks, their goals (stealing credentials, data, or installing malware).

**Identifying Red Flags:** Highlight common signs of phishing emails:

* **Suspicious sender addresses:** Don't trust emails from unknown senders or addresses that don't match the displayed name.
* **Urgent or threatening language:** Phishing emails often create a sense of urgency or fear to pressure recipients into clicking links.
* **Generic greetings:** Generic salutations like "Dear Customer" are red flags compared to personalized greetings.
* **Grammatical errors and typos:** Professional emails from legitimate companies are unlikely to contain typos or grammatical errors.
* **Suspicious attachments or links:** Never click on unsolicited attachments or links in emails, especially from unknown senders.

**Best Practices:**

*  **Verify sender legitimacy:** Before responding or clicking anything, verify the sender's identity through independent channels.
* **Don't enter personal information:** Never provide sensitive information like passwords or credit card details via email.
* **Report suspicious emails:** Report suspicious emails to the IT security team for investigation.

**Evaluation Criteria:**

* Develops a clear and concise training module for employees on identifying phishing attacks.
* Emphasizes key red flags and best practices to avoid falling victim to phishing scams.
* Promotes a culture of security awareness among employees to protect organizational

Infrastructure as Code (IaC):

Infrastructure as Code (IaC) is a practice of managing and provisioning cloud infrastructure through code files. These code files define the configuration of cloud resources (servers, networks, storage) in a human-readable and version-controlled format.

Security Implications of IaC:

Benefits:

Consistency and Repeatability: IaC ensures consistent and repeatable deployments, reducing configuration errors that can create security vulnerabilities.
Automation: Automating infrastructure provisioning allows for faster deployments and minimizes manual configuration errors.
Auditability: Version control of IaC code facilitates tracking changes and identifying potential security misconfigurations.
Security Considerations:

Misconfiguration Errors: Errors in IaC code can lead to unintended security vulnerabilities in deployed infrastructure.
Access Control: Securely manage access to IaC repositories to prevent unauthorized modifications.
Least Privilege: Implement the principle of least privilege when defining permissions within IaC scripts.
Security Scanning: Integrate security scanning tools into the CI/CD pipeline to identify potential vulnerabilities in IaC code before deployment.
Evaluation Criteria:

Accurately defines the concept of Infrastructure as Code (IaC) in the context of cloud security.
Explains the benefits of IaC for security, including consistency, repeatability, and auditability.
Identifies potential security considerations associated with IaC, such as misconfigurations and access control.
Demonstrates an understanding of secure IaC practices like least privilege and security scanning.
--------------------------------------------------------------------------

## Set 6: Hands-on, Security Concepts, and Data Flow Diagram

**1. Hands-on (Security Automation):**

**Scenario:** You are tasked with automating the process of detecting and patching vulnerabilities on your company's web servers. Describe how you would achieve this using a security automation tool.

**Evaluation Criteria:**

* Explains the concept of security automation and its benefits for vulnerability management.
* Describes the steps involved in using a security automation tool for vulnerability scanning and patching.
* Identifies key considerations like scheduling scans, prioritizing vulnerabilities, and automating patch deployment (if applicable).

**2. Security Concepts (Zero Trust Security):**

**Explain the core principles of Zero Trust Security and how it differs from traditional perimeter-based security models.**

**Evaluation Criteria:**

* Accurately defines the concept of Zero Trust Security.
* Explains the key principles of Zero Trust (e.g., least privilege, continuous verification, never trust, always verify).
* Contrasts Zero Trust with traditional perimeter-based security approaches.

**3. Data Flow Diagram:**

**Create a data flow diagram for a mobile banking application that utilizes a microservices architecture. The diagram should depict the interaction between the mobile app, authentication service, account service, transaction service, and a database.**

**Evaluation Criteria:**

* The diagram clearly represents the microservices involved (mobile app, authentication, account, transaction).
* Data flows are accurately depicted between the mobile app, services, and database.
* The diagram illustrates the interaction for user authentication, account access, and transaction processing.

**4. Hands-on (Security Policy Enforcement):**

**You are updating your company's password policy. Describe the specific security controls you would implement to enforce the new policy and ensure user compliance.**

**Evaluation Criteria:**

* Identifies technical controls for enforcing password complexity requirements (e.g., password length, character types).
* Explains user education and awareness initiatives to promote strong password practices.
* Discusses potential monitoring and auditing mechanisms to track password compliance.

**5. Security Concepts (Social Engineering):**

**Describe different social engineering techniques attackers use and how employees can be trained to identify and avoid them.**

**Evaluation Criteria:**

* Explains common social engineering techniques (e.g., phishing, pretexting, baiting).
* Identifies red flags and suspicious behaviors associated with social engineering attempts.
* Discusses training methods to educate employees on social engineering tactics and best practices for avoiding them (e.g., verification procedures, not clicking suspicious links).
