Thank you for sharing the image with the rules listed under DRS 2.1. Below is an updated table capturing these rules and providing a brief description for each.

### Document: Creation and Implementation of Base/Parent Azure WAF Policies for Azure Application Gateway and Azure Front Door

---

#### 1. **Introduction**
   - **Objective:** This document outlines the creation and implementation of base/parent Web Application Firewall (WAF) policies in Azure. These policies will be applied to both Azure Application Gateway and Azure Front Door, providing a unified security posture across different platforms.
   - **Scope:** The document covers the design principles, configuration steps, and deployment strategy for base WAF policies that can be inherited by child policies for specific applications.

#### 2. **Purpose of Base/Parent WAF Policies**
   - **Unified Security Baseline:** Establish a consistent set of security controls across all web applications by defining a base WAF policy that includes common protections.
   - **Ease of Management:** Centralize the management of common security rules while allowing for customization through child policies that can be tailored to specific application needs.
   - **Scalability and Efficiency:** Leverage the parent-child relationship in WAF policies to scale security configurations across multiple applications without duplicating effort.

#### 3. **Base WAF Policy Configuration**

##### **Table 1: BaseWAFPolicy Configuration Details**

| **Policy Attribute**           | **Description**                                                                                                                                                          | **Details**                                                                                                                                                   | **Purpose/Impact**                                                                                                     |
|--------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------|
| **Policy Name**                | Name of the base WAF policy.                                                                                                                                              | `BaseWAFPolicy`                                                                                                                                               | Serves as the parent policy from which child policies inherit common configurations.                                     |
| **Policy Type**                | Indicates that this is a parent policy.                                                                                                                                   | Parent Policy                                                                                                                                                | Ensures consistent enforcement of security rules across all associated child policies.                                   |
| **Application Scope**          | Defines the applications or services the policy will apply to.                                                                                                           | Azure Application Gateway and Azure Front Door                                                                                                               | Provides centralized management for applications across different Azure services.                                        |
| **Rule Set Version**           | The version of the default rule set provided by Microsoft for WAF.                                                                                                       | `Microsoft_DefaultRuleSet_2.1`                                                                                                                               | Ensures that the latest security rules are enforced, protecting against OWASP Top 10 and other vulnerabilities.          |
| **Custom Rules**               | Additional security rules defined by the organization to address specific threats.                                                                                       | - **IP Restriction**: Allows or blocks traffic based on IP address.<br>- **Rate Limiting**: Limits the number of requests per IP.<br>- **Bot Protection**: Blocks known malicious user agents. | Addresses specific organizational security requirements not covered by the default rule set.                             |
| **IP Restriction Rules**       | Rules to restrict or allow traffic based on IP addresses.                                                                                                                | - **Allow List**: Trusted IP ranges.<br>- **Block List**: Malicious IP ranges.<br>- **Geo-Blocking**: Restrict access based on geographical locations.        | Controls access to applications, reducing the risk of unauthorized or malicious traffic.                                 |
| **Rate Limiting**              | Limits the rate of requests to prevent denial-of-service attacks.                                                                                                        | 1000 requests per minute per IP                                                                                                                               | Helps to mitigate Denial of Service (DoS) attacks by preventing excessive requests from a single IP address.             |
| **Bot Protection**             | Blocks traffic from known malicious bots and user agents.                                                                                                                | Blocks requests from known malicious user agents based on User-Agent header                                                                                  | Protects web applications from automated attacks, such as scraping, DDoS, and brute force attacks.                       |
| **HTTP Protocol Anomalies**    | Detects and blocks anomalous HTTP requests that do not conform to expected protocol standards.                                                                            | Inspects HTTP requests for protocol violations and blocks them if detected                                                                                    | Prevents evasion techniques and malformed requests that could be indicative of an attack.                                |
| **File Upload Protection**     | Limits the size of files that can be uploaded through the application to prevent resource exhaustion.                                                                     | Maximum file size: 10MB                                                                                                                                       | Prevents attackers from uploading excessively large files that could lead to resource exhaustion or exploitation.        |
| **Logging**                    | Configuration for logging WAF activity, including blocked requests and rule matches.                                                                                     | Logs all requests blocked by WAF, including details of the rule that triggered the block.                                                                     | Provides visibility into WAF activities, aiding in incident response and forensic investigations.                        |
| **Log Retention**              | Duration for which logs will be retained for audit and compliance purposes.                                                                                               | 90 days                                                                                                                                                       | Ensures logs are available for compliance audits, incident investigations, and historical analysis.                      |
| **SIEM Integration**           | Integration with a Security Information and Event Management (SIEM) system for centralized monitoring and alerting.                                                       | Forward WAF logs to the organization's SIEM for real-time monitoring and correlation of security events.                                                     | Centralizes security event management, enabling proactive detection and response to potential threats.                   |
| **Monitoring and Tuning**      | Continuous process of monitoring WAF activity and adjusting the policy to reduce false positives and improve security coverage.                                           | Regular review of WAF logs, rule adjustments based on observed traffic patterns, and fine-tuning to balance security with application usability.              | Enhances the effectiveness of the WAF policy by ensuring it adapts to the evolving threat landscape and application needs. |

##### **Table 2: Microsoft_DefaultRuleSet_2.1 Rules**

| **Rule Name**                                 | **Description**                                                                                         | **Threat Addressed**                               | **Status**                    |
|-----------------------------------------------|---------------------------------------------------------------------------------------------------------|---------------------------------------------------|--------------------------------|
| **General**                                   | General security rules covering common attack patterns and protocol enforcement.                         | Various (e.g., malformed requests)                | Enabled                        |
| **METHOD-ENFORCEMENT**                        | Ensures that only allowed HTTP methods (GET, POST, etc.) are used.                                        | HTTP Method Exploits                              | Enabled                        |
| **PROTOCOL-ENFORCEMENT**                      | Enforces proper use of HTTP/HTTPS protocols to prevent protocol misuse.                                   | Protocol Misuse                                   | Enabled                        |
| **PROTOCOL-ATTACK**                           | Detects and blocks attacks that exploit vulnerabilities in protocol implementations.                      | Protocol Exploits                                 | Enabled                        |
| **APPLICATION-ATTACK-LFI**                    | Blocks attempts to exploit Local File Inclusion vulnerabilities.                                          | Local File Inclusion (LFI)                        | Enabled                        |
| **APPLICATION-ATTACK-RFI**                    | Blocks attempts to exploit Remote File Inclusion vulnerabilities.                                         | Remote File Inclusion (RFI)                       | Enabled                        |
| **APPLICATION-ATTACK-RCE**                    | Prevents attacks that attempt to execute remote code on the server.                                        | Remote Code Execution (RCE)                       | Enabled                        |
| **APPLICATION-ATTACK-PHP**                    | Detects and blocks PHP-specific attack patterns.                                                          | PHP Exploits                                      | Enabled                        |
| **APPLICATION-ATTACK-NodeJS**                 | Blocks attacks targeting Node.js-based applications.                                                      | Node.js Exploits                                  | Enabled                        |
| **APPLICATION-ATTACK-XSS**                    | Prevents Cross-Site Scripting attacks that inject malicious scripts into web pages.                       | Cross-Site Scripting (XSS)                        | Enabled                        |
| **APPLICATION-ATTACK-SQLI**                   | Blocks SQL Injection attacks that attempt to manipulate SQL queries.                                       | SQL Injection (SQLI)                              | Enabled                        |
| **APPLICATION-ATTACK-SESSION-FIXATION**       | Detects and prevents session fixation attacks, which involve hijacking a user session.                    | Session Fixation                                  | Enabled                        |
| **APPLICATION-ATTACK-SESSION-JAVA**           | Detects session management vulnerabilities specific to Java applications.                                  | Java Session Management Exploits                  | Enabled                        |
| **MS-ThreatIntel-WebShells**                  | Microsoft Threat Intelligence rules to detect and block web shells.                                       | Web Shells                                        | Enabled                        |
| **MS-ThreatIntel-AppSec**                     | Application security rules informed by Microsoft's Threat Intelligence.                                    | Various Application-Level Threats                 | Enabled                        |
| **MS-ThreatIntel-SQLI**                       | SQL Injection rules informed by Microsoft's Threat Intelligence.                                           | SQL Injection                                     | Enabled                        |
| **MS-ThreatIntel-CVEs**                       | Blocks known vulnerabilities (Common Vulnerabilities and Exposures) identified by Microsoft's Threat Intelligence. | Various CVE Exploits                              | Enabled                        |

*Note: Some rules are informed by Microsoft's Threat Intelligence (MSTIC) and are updated to reflect the latest security intelligence. Rules that overlap with MSTIC may be disabled if covered more effectively by MSTIC rules.*

#### 4. **Inheritance and Customization in Child Policies**
   - **Inheritance Mechanism:** Child WAF policies applied to specific Azure Application Gateways or Front Door instances will inherit the base rules and settings from the parent policy.
   - **Customization Options:**
     - **Override Rules:** Child policies can override specific rules from the base policy to address unique application requirements.
     - **Additional Custom Rules:** Child policies can include additional rules tailored to the specific threats and risks associated with individual applications.

##### **Table 3: Example of Child Policy Customization**

| **Child Policy Name** | **Inherited Rules from Base Policy**                                    | **Customizations/Overrides**                                          | **Application-Specific Considerations**                                                        |
|-----------------------|--------------------------------------------------------------------------|------------------------------------------------------------------------|------------------------------------------------------------------------------------------------|
| WebApp1_WAFPolicy      | - Microsoft_DefaultRuleSet_2.1<br>- IP Restriction<br>- Rate Limiting  

 | - Increased request limit to 2000 per minute per IP due to high traffic.| WebApp1 requires higher throughput due to its nature as a high-traffic public-facing application. |
| InternalApp_WAFPolicy  | - Microsoft_DefaultRuleSet_2.1<br>- IP Restriction                      | - Custom IP allow list for internal IP ranges only.<br>- Disabled geo-blocking. | InternalApp is accessed only from specific internal IP ranges and does not require geo-blocking. |
| API_WAFPolicy          | - Microsoft_DefaultRuleSet_2.1<br>- Rate Limiting<br>- Logging          | - Added additional custom rule to block specific API endpoints from public access. | API_WAFPolicy protects APIs, requiring more granular control over endpoint access.              |

#### 5. **Implementation Plan**

##### **5.1 Policy Creation**
   - **Step 1: Define Base WAF Policy**
     - In the Azure portal, navigate to the WAF policies section.
     - Create a new WAF policy, selecting the "Parent" option.
     - Configure the base policy with the default rule set, custom rules, and logging settings as outlined in Section 3.
   - **Step 2: Define Child Policies**
     - Create child WAF policies that inherit the base policy settings.
     - Customize the child policies as needed to address specific application requirements.

##### **5.2 Policy Deployment**
   - **Step 1: Apply Base Policy to Azure Application Gateway**
     - Associate the base WAF policy with the relevant Azure Application Gateway instances.
   - **Step 2: Apply Base Policy to Azure Front Door**
     - Associate the base WAF policy with the relevant Azure Front Door profiles.
   - **Step 3: Validate Configuration**
     - Conduct testing in a staging environment to ensure that the policies are correctly applied and functioning as expected.
   - **Step 4: Rollout to Production**
     - Gradually roll out the WAF policies to production environments, starting with non-critical applications.

#### 6. **Monitoring and Tuning**
   - **Continuous Monitoring:** Regularly monitor WAF logs and SIEM alerts to detect any anomalies or issues with the applied policies.
   - **Fine-Tuning:** Adjust the base and child policies as needed to minimize false positives and optimize security coverage.
   - **Periodic Reviews:** Conduct regular reviews of the WAF policy configuration to ensure it aligns with the evolving threat landscape and business needs.

#### 7. **Risk Assessment**
   - **Risk of Not Implementing:** The absence of a unified WAF policy increases the risk of inconsistent security controls and vulnerabilities across applications.
   - **Risk of Implementation:** Potential risks include performance impacts, false positives, and the need for ongoing policy maintenance.

#### 8. **Conclusion and Recommendation**
   - **Conclusion:** Implementing a base/parent WAF policy across Azure Application Gateway and Azure Front Door provides a consistent and scalable security solution that aligns with industry best practices.
   - **Recommendation:** It is recommended to proceed with the creation and deployment of the base WAF policy, followed by the implementation of child policies for specific applications.

#### 9. **Appendices**
   - **Appendix A:** Detailed rule descriptions for `Microsoft_DefaultRuleSet_2.1`.
   - **Appendix B:** Sample configurations for custom rules.
   - **Appendix C:** References to Azure documentation and WAF best practices.

---

This document should be reviewed by the security team, application owners, network engineers, and other relevant stakeholders before final approval and implementation. The goal is to ensure that all parties understand the implications of the base WAF policy and are prepared to manage any necessary follow-up actions.



Certainly! Below is an updated version of **Table 1** that includes the policy definitions for all customized rules in the **BaseWAFPolicy**.

### **Table 1: BaseWAFPolicy Configuration Details**

| **Policy Attribute**           | **Description**                                                                                                                                                          | **Details**                                                                                                                                                   | **Purpose/Impact**                                                                                                     |
|--------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------|
| **Policy Name**                | Name of the base WAF policy.                                                                                                                                              | `BaseWAFPolicy`                                                                                                                                               | Serves as the parent policy from which child policies inherit common configurations.                                     |
| **Policy Type**                | Indicates that this is a parent policy.                                                                                                                                   | Parent Policy                                                                                                                                                 | Ensures consistent enforcement of security rules across all associated child policies.                                   |
| **Application Scope**          | Defines the applications or services the policy will apply to.                                                                                                           | Azure Application Gateway and Azure Front Door                                                                                                               | Provides centralized management for applications across different Azure services.                                        |
| **Rule Set Version**           | The version of the default rule set provided by Microsoft for WAF.                                                                                                       | `Microsoft_DefaultRuleSet_2.1`                                                                                                                               | Ensures that the latest security rules are enforced, protecting against OWASP Top 10 and other vulnerabilities.          |
| **Custom Rule: IP Restriction**| Rules to restrict or allow traffic based on IP addresses.                                                                                                                | **Definition**: <br>- `match` conditions based on IP ranges <br>- **Action**: Allow or Block traffic based on matched IP ranges <br>- **Geo-Blocking**: Restrict access based on geographical locations.        | Controls access to applications, reducing the risk of unauthorized or malicious traffic.                                 |
| **Custom Rule: Rate Limiting** | Limits the rate of requests to prevent denial-of-service attacks.                                                                                                        | **Definition**: <br>- `match` conditions based on the number of requests from a single IP address<br>- **Threshold**: 1000 requests per minute per IP <br>- **Action**: Block IPs exceeding the threshold.                                                                                                                              | Helps to mitigate Denial of Service (DoS) attacks by preventing excessive requests from a single IP address.             |
| **Custom Rule: Bot Protection**| Blocks traffic from known malicious bots and user agents.                                                                                                                | **Definition**: <br>- `match` conditions based on User-Agent headers <br>- **Action**: Block requests from identified malicious user agents or bots.                                                                                                                            | Protects web applications from automated attacks, such as scraping, DDoS, and brute force attacks.                       |
| **Custom Rule: HTTP Protocol Anomalies** | Detects and blocks anomalous HTTP requests that do not conform to expected protocol standards.                                                                            | **Definition**: <br>- `match` conditions based on HTTP protocol anomalies such as malformed headers, non-standard HTTP methods, or unusual payloads.<br>- **Action**: Block or log suspicious requests. | Prevents evasion techniques and malformed requests that could be indicative of an attack.                                |
| **File Upload Protection**     | Limits the size of files that can be uploaded through the application to prevent resource exhaustion.                                                                     | **Definition**: <br>- `match` conditions based on file size in upload requests <br>- **Maximum file size**: 10MB <br>- **Action**: Block requests that exceed the allowed file size.                                                                                                                              | Prevents attackers from uploading excessively large files that could lead to resource exhaustion or exploitation.        |
| **Logging**                    | Configuration for logging WAF activity, including blocked requests and rule matches.                                                                                     | **Definition**: <br>- Logs all requests blocked by WAF, including details of the rule that triggered the block <br>- **Log Retention**: 90 days <br>- **Integration**: Forward logs to SIEM system. | Provides visibility into WAF activities, aiding in incident response and forensic investigations.                        |
| **Log Retention**              | Duration for which logs will be retained for audit and compliance purposes.                                                                                               | 90 days                                                                                                                                                       | Ensures logs are available for compliance audits, incident investigations, and historical analysis.                      |
| **SIEM Integration**           | Integration with a Security Information and Event Management (SIEM) system for centralized monitoring and alerting.                                                       | **Definition**: <br>- Forwards WAF logs to the organization's SIEM for real-time monitoring and correlation of security events.                                                                     | Centralizes security event management, enabling proactive detection and response to potential threats.                   |
| **Monitoring and Tuning**      | Continuous process of monitoring WAF activity and adjusting the policy to reduce false positives and improve security coverage.                                           | **Definition**: <br>- Regular review of WAF logs, rule adjustments based on observed traffic patterns, and fine-tuning to balance security with application usability.                                                                                                                              | Enhances the effectiveness of the WAF policy by ensuring it adapts to the evolving threat landscape and application needs. |

### Explanation of Customized Rules:
1. **IP Restriction**: This rule matches incoming requests against a list of allowed or blocked IP addresses and geographic locations. If a request comes from a blocked IP or a restricted geographic region, the WAF will block the request.

2. **Rate Limiting**: This rule monitors the rate of requests from individual IP addresses. If the number of requests from a single IP exceeds the defined threshold (e.g., 1000 requests per minute), the WAF will block further requests from that IP for a set period.

3. **Bot Protection**: This rule looks for known malicious user-agent strings in HTTP requests. If a request's User-Agent header matches one known to be associated with bots or malicious activities, the WAF will block the request.

4. **HTTP Protocol Anomalies**: This custom rule focuses on detecting and blocking requests that do not follow standard HTTP protocols. For instance, it can block requests with malformed headers, non-standard HTTP methods, or unusual payloads that could indicate an attack attempt or a probe.

5. **File Upload Protection**: This rule restricts the size of files that can be uploaded via the application. If a file exceeds the maximum allowed size (e.g., 10MB), the WAF blocks the upload, protecting the server from potential resource exhaustion attacks.




Certainly! Below is an updated version of the **HTTP Rule** table that uses the **`notIn`** operator to block any HTTP methods that are not part of the standard methods (`GET`, `HEAD`, `POST`, `PUT`, `DELETE`, `PATCH`, `OPTIONS`).

### **Consolidated Table: Custom Rules for HTTP, Bot Protection, and Geo-Restriction**

| **Rule Name**                 | **Description**                                                   | **Match Variables**                              | **Operator**           | **Match Values**                                                                    | **Action** | **Priority** | **Purpose/Impact**                                                                 |
|-------------------------------|-------------------------------------------------------------------|-------------------------------------------------|------------------------|-------------------------------------------------------------------------------------|------------|--------------|-------------------------------------------------------------------------------------|
| **HTTP Rule**                 | Detects and blocks requests with malformed headers.               | `RequestHeaders`                                | `Contains`              | `\r\n`, `\n`, `\r`, `:`, `;;`, `\0`                                                 | `Block`    | 1            | Prevents attacks using malformed headers, such as HTTP Response Splitting or Injection. |
| **HTTP Rule**                 | Detects and blocks non-standard or potentially dangerous HTTP methods. | `RequestMethod`                                | `notIn`                 | `["GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]`                     | `Block`    | 2            | Ensures that only standard, allowed HTTP methods are used, blocking non-standard methods that could be exploited. |
| **HTTP Rule**                 | Detects and blocks requests with unusual payloads.                | `RequestBody`<br>`RequestHeaders['Content-Type']` | `SizeGreaterThan`<br>`Equal` | `1048576` (1 MB size limit)<br>`application/octet-stream`, `text/xml`, `application/x-www-form-urlencoded` | `Block`    | 3            | Protects against attacks using unusually large payloads or unexpected content types. |
| **Bot Protection**            | Detects and blocks requests from known bad bots.                  | `RequestHeaders['User-Agent']`                  | `Equal`                 | `BadBot`, `EvilBot`, `Scrapy`, `Python-urllib`, `libwww-perl`, `curl`, `wget`      | `Block`    | 4            | Prevents access from bots known to engage in scraping, brute force, and other malicious activities. |
| **Bot Protection**            | Detects and blocks requests from headless browsers.               | `RequestHeaders['User-Agent']`                  | `Contains`              | `HeadlessChrome`, `PhantomJS`, `SlimerJS`, `Zombie`, `Node.js`                     | `Block`    | 5            | Blocks requests from headless browsers often used in automated attacks and scraping. |
| **Bot Protection**            | Detects and blocks requests with empty or missing user-agent headers. | `RequestHeaders['User-Agent']`                  | `Equal`                 | `""` (Empty String)                                                                | `Block`    | 6            | Prevents access from bots and scripts that do not provide a user-agent, a common characteristic of malicious activity. |
| **Geo-Restriction**           | Blocks access from sanctioned countries.                          | `RequestHeaders['X-Forwarded-For']`<br>`GeoIP`  | `In`                    | List of sanctioned countries, e.g., `IR`, `KP`, `SY`, `CU`, `RU`, `VE`, `SD`       | `Block`    | 7            | Prevents access to the application from countries under international sanctions.     |

### Summary:

- **HTTP Rule**: 
  - **Malformed Headers**: Blocks requests with improperly formatted or suspicious headers.
  - **Non-Standard HTTP Methods**: Blocks HTTP methods that are not part of the standard set (`GET`, `HEAD`, `POST`, `PUT`, `DELETE`, `PATCH`, `OPTIONS`) to prevent exploitation through unsupported or unsafe methods.
  - **Unusual Payloads**: Blocks requests with unusually large payloads or unexpected content types.

- **Bot Protection**:
  - **Known Bad Bots**: Blocks traffic from bots known for malicious activities based on their User-Agent string.
  - **Headless Browsers**: Blocks requests from headless browsers, often used for automated attacks.
  - **Empty User-Agent**: Blocks requests where the User-Agent header is missing or empty.

- **Geo-Restriction**:
  - **Sanctioned Countries**: Blocks access to your application from countries under international sanctions.

This version of the table clearly separates each rule's functionality while ensuring that HTTP methods outside the standard set are effectively blocked.
6. **Logging and SIEM Integration**: This ensures that all actions taken by the WAF are logged and stored for later analysis. These logs are also forwarded to a SIEM system for centralized monitoring, enabling real-time alerting and incident response.

These customized rules in the **BaseWAFPolicy** ensure that you have a robust defense against common web application threats while allowing for flexibility and adaptability in response to specific organizational needs.
