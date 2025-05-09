# Security Alert Verification Checklist

## 1. Endpoint Security Alerts (CrowdStrike Falcon)

### Malware Detection Verification
- [ ] Process execution chain and parent-child relationships
- [ ] File hash validation against threat intelligence
- [ ] Static and dynamic analysis results of the suspicious file
- [ ] File creation timestamp and source
- [ ] User context and privileges during execution
- [ ] Command line arguments used for execution
- [ ] Network connections initiated by the process
- [ ] Registry modifications made by the process
- [ ] Similar activity on other endpoints in the environment

### Suspicious PowerShell/Command Line Activity
- [ ] Full command line syntax and parameters
- [ ] User executing the command (privileged vs. standard)
- [ ] Time of execution (business hours vs. off-hours)
- [ ] Authentication method used for the session
- [ ] Previous commands executed in the same session
- [ ] Output and results of the command execution
- [ ] Historical baseline of PowerShell usage for the user/system
- [ ] Encoded command content (if obfuscated)
- [ ] System or configuration changes resulting from execution

### Behavioral Indicators
- [ ] Context of the user's normal activity patterns
- [ ] Presence of legitimate administrative activities
- [ ] Correlation with change management records
- [ ] Endpoint performance metrics at time of alert
- [ ] Recently installed applications or updates
- [ ] Concurrent security tool alerts
- [ ] Previous alerts from the same endpoint

## 2. Network Security Alerts (Zscaler)

### Suspicious Connection Verification
- [ ] Full connection details (source, destination, ports, protocol)
- [ ] DNS resolution history for the domain
- [ ] SSL/TLS certificate information
- [ ] Domain age and reputation
- [ ] Geographic location of external IPs
- [ ] Volume and frequency of communications
- [ ] Packet capture analysis (if available)
- [ ] User identity associated with the connection
- [ ] Application generating the traffic
- [ ] Similar connection patterns from other internal hosts

### Data Exfiltration Indicators
- [ ] Data volume transferred compared to baseline
- [ ] File types being transferred
- [ ] Connection duration and timing
- [ ] Destination categorization and reputation
- [ ] Protocol analysis for covert channels
- [ ] Evidence of compression or encryption
- [ ] Business justification for data transfer
- [ ] User authorization for data access
- [ ] Previous data transfer patterns for the user/system

### Unauthorized Access Attempts
- [ ] Source IP reputation and history
- [ ] Authentication logs correlating with access attempts
- [ ] Pattern and frequency of attempts
- [ ] Resources being targeted
- [ ] Technique signatures (e.g., specific vulnerability exploitation)
- [ ] Historical access patterns to the target resource
- [ ] Geographic origin of access attempts
- [ ] Time of access attempts relative to business hours

## 3. Email Security Alerts (Proofpoint)

### Phishing Email Verification
- [ ] Full email headers for source validation
- [ ] Sender domain age and reputation
- [ ] Email authentication results (SPF, DKIM, DMARC)
- [ ] URL reputation and sandboxing results
- [ ] Attachment analysis results
- [ ] Similar emails to other recipients
- [ ] Content analysis for social engineering tactics
- [ ] Historical communication with the sender
- [ ] Relevance of the email content to recipient's role

### Malicious Attachment Verification
- [ ] File hash comparison against threat intelligence
- [ ] Sandbox detonation results
- [ ] File type analysis and hidden extensions
- [ ] Embedded macros or scripts analysis
- [ ] Extraction of URLs or IP addresses from the file
- [ ] Behavioral analysis results
- [ ] Static analysis indicators
- [ ] Comparison to known legitimate file versions
- [ ] Presence of the same file hash in other emails

### Business Email Compromise (BEC) Verification
- [ ] Sender email address vs. display name discrepancies
- [ ] Historical communication patterns with the sender
- [ ] Email tone and urgency indicators
- [ ] Unusual requests or instructions
- [ ] Validation of actual email owner (if impersonation)
- [ ] Recent account compromise indicators
- [ ] Similar targeting of other executives/employees
- [ ] Domain similarity to legitimate domains (lookalike domains)

## 4. Cloud Security Alerts (AWS CloudTrail, GuardDuty)

### Unusual API Activity
- [ ] User identity performing the API call
- [ ] Authentication method and source IP
- [ ] API call history for the user
- [ ] Time of API calls relative to user's normal patterns
- [ ] Success/failure status of the calls
- [ ] Resources accessed or modified
- [ ] Business justification for the API activity
- [ ] Related API calls in the same session
- [ ] Geographic location of API calls

### Suspicious Resource Deployment
- [ ] Identity creating the resources
- [ ] Resource configuration and permissions
- [ ] Comparison to established infrastructure patterns
- [ ] Tags and naming conventions used
- [ ] Network connectivity of new resources
- [ ] Associated change management tickets
- [ ] Time of resource creation
- [ ] Cost and scale of deployed resources
- [ ] Previous similar deployments by the same user

### Unusual Authentication Events
- [ ] Authentication source (IP, device, location)
- [ ] Authentication method used
- [ ] Time of authentication attempts
- [ ] Success/failure patterns
- [ ] Resources accessed after authentication
- [ ] User's normal authentication patterns
- [ ] MFA status and bypass attempts
- [ ] Concurrent sessions from different locations
- [ ] Password change or credential modification events

## 5. SIEM/XDR Correlation Alerts (Secureworks XDR)

### Alert Correlation Verification
- [ ] Timeline of all correlated events
- [ ] Relationship between the events
- [ ] Common identifiers across events (user, IP, process)
- [ ] Progression of potential attack stages
- [ ] Context of each individual alert
- [ ] Severity and confidence levels of individual alerts
- [ ] False positive history for similar alert patterns
- [ ] Supporting evidence from different data sources
- [ ] Business context of affected systems/users

### Anomalous Behavior Detection
- [ ] Baseline deviation metrics
- [ ] Historical patterns for the affected entity
- [ ] Context of business operations (changes, maintenance)
- [ ] Concurrent anomalies in related systems
- [ ] User activity before and after the anomaly
- [ ] Environmental factors that might explain the anomaly
- [ ] Similar historical alerts and their resolutions
- [ ] Data quality issues that might affect detection

### Threat Intelligence Matches
- [ ] Confidence level of the intelligence source
- [ ] Age of the threat intelligence indicator
- [ ] Context of the original threat intelligence
- [ ] Prevalence of the indicator in your environment
- [ ] Associated activity surrounding the indicator
- [ ] False positive rate for the intelligence source
- [ ] Relevance of the threat actor to your organization
- [ ] Additional supporting evidence beyond the match

## 6. Vulnerability Management Alerts (Tenable Nessus)

### Critical Vulnerability Detection
- [ ] Vulnerability details and CVE information
- [ ] Exploitability assessment
- [ ] Affected system's exposure (internet-facing vs. internal)
- [ ] Validation of vulnerability (false positive testing)
- [ ] Presence of mitigating controls
- [ ] Patch availability and testing status
- [ ] Business criticality of affected systems
- [ ] Exploitation attempts against the vulnerability
- [ ] Similar vulnerable systems in the environment

### Misconfiguration Alerts
- [ ] Configuration standard being violated
- [ ] Security impact of the misconfiguration
- [ ] Duration of the misconfiguration
- [ ] Recent changes to the system
- [ ] Business justification for the configuration
- [ ] Approved exceptions documentation
- [ ] Detection of exploitation attempts
- [ ] System owner awareness of the configuration
- [ ] Similar misconfigurations across the environment

# Alert Verification Scenarios

## Scenario 1: Endpoint Malware Alert (CrowdStrike Falcon)

**Alert Details:**
CrowdStrike Falcon has detected a suspicious executable with a machine learning score indicating potential malware on a finance department workstation.

**Verification Process:**

1. "First, I check the process execution chain using Falcon's process explorer to understand how the executable was launched. I notice it was spawned from outlook.exe, suggesting an email vector."

2. "I examine the file hash and discover it's not known in threat intelligence feeds but has suspicious characteristics. The static analysis reveals it's a heavily obfuscated PowerShell script compiled to an executable."

3. "Looking at the user context, I confirm this is a regular finance employee without administrative privileges, making this execution suspicious."

4. "I review the network connections initiated by the process and identify callbacks to an unknown domain registered only 2 days ago - a strong indicator of malicious activity."

5. "Finally, I check for similar detections across our environment and find two other finance employees received the same file but CrowdStrike blocked execution on their devices."

**Conclusion:**
"Based on the process chain originating from email, the obfuscated code, communication with newly registered domains, and the targeting pattern across finance employees, I determine this is a TRUE POSITIVE - likely a targeted phishing attack against our finance department requiring immediate incident response."

## Scenario 2: Network Data Exfiltration Alert (Zscaler)

**Alert Details:**
Zscaler has flagged unusual outbound data transfer to an unknown cloud storage service from a marketing department workstation, with 2.3GB of data transferred outside normal business hours.

**Verification Process:**

1. "I begin by examining the connection details, confirming outbound HTTPS traffic to a file-sharing service that's not on our approved list, occurring at 11:30 PM local time."

2. "Looking at the user's baseline, I verify this employee typically works 9-5 and rarely accesses systems after hours. The volume of data transferred also exceeds their normal patterns."

3. "I check user authentication logs and notice their account accessed the VPN at 11:15 PM from a geographic location different from their normal work or home locations."

4. "Examining the files being transferred using DLP logs, I identify multiple marketing strategy documents and customer segmentation data with sensitive classification."

5. "I review recent security events and discover a successful phishing attempt against this user earlier in the day, which they didn't report."

**Conclusion:**
"This is a TRUE POSITIVE incident. The combination of after-hours activity, unusual location, large data transfer of sensitive files to an unapproved service, and the earlier successful phishing attempt strongly indicates a compromised account being used for data exfiltration."

## Scenario 3: False Positive PowerShell Alert (CrowdStrike)

**Alert Details:**
CrowdStrike has flagged suspicious PowerShell activity with encoded commands on an IT administrator's workstation, potentially indicating malicious activity.

**Verification Process:**

1. "I begin by decoding the Base64 encoded PowerShell command and analyze the script content, finding it's executing Microsoft 365 administration commands."

2. "I verify the user is a legitimate IT administrator responsible for Microsoft 365 management, and the activity occurred during their normal work hours."

3. "I check our change management system and confirm there's an approved ticket for Microsoft 365 user provisioning maintenance scheduled for today."

4. "I review the administrator's historical PowerShell usage and find similar encoded commands are regularly used as part of their legitimate administration tasks."

5. "I examine the command's effects, confirming they align with the expected changes from the maintenance ticket - creating new user accounts and configuring mailboxes."

**Conclusion:**
"This is a FALSE POSITIVE alert. The encoded PowerShell commands are legitimate administration activities by an authorized administrator, executed during business hours with an approved change ticket, and consistent with their normal activity patterns for Microsoft 365 management."

## Scenario 4: Cloud Infrastructure Alert (AWS GuardDuty)

**Alert Details:**
AWS GuardDuty has detected unusual API calls creating EC2 instances in a region never used before, with cryptomining software installation attempts.

**Verification Process:**

1. "I immediately check the IAM user that initiated these API calls and discover it's a service account used for our CI/CD pipeline."

2. "I examine the authentication logs and notice the service account credentials were used from an IP address in Eastern Europe, outside our normal operational regions."

3. "I verify there are no change management tickets or business justifications for deploying resources in this new region."

4. "I analyze the EC2 instance configuration and confirm they're using high-CPU instance types with no security groups limiting access - unusual for our standard deployments."

5. "I check CloudTrail logs and identify successful attempts to disable CloudWatch logging on these instances immediately after creation."

**Conclusion:**
"This is a clear TRUE POSITIVE security incident. The service account appears compromised and is being used to deploy cryptomining infrastructure in an unused region. The attempts to disable logging further confirm malicious intent. This requires immediate incident response to revoke the credentials and terminate the unauthorized resources."

## Scenario 5: False Positive Email Alert (Proofpoint)

**Alert Details:**
Proofpoint has quarantined multiple emails with PDF attachments sent to your finance team, flagging them as potential phishing attempts with malicious attachments.

**Verification Process:**

1. "I first examine the sender domain and verify it belongs to our legitimate tax consulting firm with whom we have an established relationship."

2. "I analyze the email headers and confirm they pass SPF, DKIM, and DMARC authentication, indicating the emails are genuinely from this domain."

3. "I conduct sandbox analysis of the PDF attachments, finding they contain only expected tax documents with no malicious code, links, or embedded content."

4. "I check with the finance department and verify they were expecting these tax documents as part of our quarterly tax filing process."

5. "I review our communication history with this firm and confirm similar legitimate emails with PDF attachments are regularly exchanged during tax seasons."

**Conclusion:**
"This is a FALSE POSITIVE alert. The emails are legitimate communications from our tax consultants containing expected tax documents. The detection was likely triggered by keywords related to financial transactions in the PDFs. I would release the emails from quarantine and adjust our detection rules to reduce similar false positives in the future."

## Scenario 6: Web Application Attack Alert (Secureworks XDR)

**Alert Details:**
Secureworks XDR has correlated multiple alerts indicating potential SQL injection attempts against your customer portal, with some attempts showing successful query syntax.

**Verification Process:**

1. "I analyze the HTTP requests and confirm they contain classic SQL injection patterns attempting to extract database schema information."

2. "I check the source IPs and discover they're coming from known malicious scanner networks and Tor exit nodes."

3. "I review the application logs to determine if the injection attempts were successful and find error messages indicating SQL syntax errors in the logs."

4. "I verify the application's database activity monitoring and observe unusual queries that match the injection patterns reaching the database."

5. "I check for any data exfiltration indicators and identify abnormally large response sizes to some of the requests, suggesting successful data extraction."

**Conclusion:**
"This is a confirmed TRUE POSITIVE attack. The evidence shows active SQL injection attempts from malicious sources with signs of successful exploitation and potential data exfiltration. This requires immediate incident response to patch the vulnerability, analyze the extent of compromise, and contain the incident."

## Scenario 7: Authentication Alert (Secureworks XDR and AWS CloudTrail)

**Alert Details:**
Secureworks XDR has correlated multiple failed VPN authentication attempts for an executive account, followed by a successful AWS console login from an unusual location.

**Verification Process:**

1. "I first check the VPN authentication logs and confirm 12 failed login attempts for our CFO's account over a 3-minute period, followed by a successful authentication."

2. "I verify the successful authentication originated from Romania, while our CFO is known to be in the United States with no travel plans."

3. "I analyze the AWS CloudTrail logs and confirm the same account successfully authenticated to the AWS console 5 minutes after the VPN access."

4. "I review the AWS activity and discover attempts to modify IAM permissions and access S3 buckets containing financial data."

5. "I contact the CFO directly through our out-of-band communication channel, who confirms they have not attempted to log in to any systems in the last 24 hours."

**Conclusion:**
"This is a HIGH-PRIORITY TRUE POSITIVE security incident indicating a likely compromised executive account. The evidence points to a successful brute force attack against the VPN followed by cloud account access from an unauthorized location. The attempt to escalate privileges in AWS further confirms malicious intent. This requires immediate incident response including account lockdown, credential reset, and forensic investigation."

## Scenario 8: Vulnerability Exploitation Alert (Tenable Nessus and Secureworks XDR)

**Alert Details:**
Tenable Nessus identified a critical vulnerability in your public-facing web application yesterday. Today, Secureworks XDR has detected exploitation patterns targeting that specific vulnerability.

**Verification Process:**

1. "I first confirm the vulnerability details from the Nessus scan, identifying it as a critical authentication bypass in our customer portal that was discovered during yesterday's scan."

2. "I check our patch management system and confirm the application has not yet been patched, as the patch was scheduled for this weekend's maintenance window."

3. "I analyze the web server logs and identify request patterns that match known exploitation techniques for this specific vulnerability."

4. "I review the application authentication logs and discover successful logins without corresponding credentials being validated, confirming successful exploitation."

5. "I examine post-exploitation activity and find evidence of unauthorized access to customer records and attempts to inject web shells for persistence."

**Conclusion:**
"This is a CRITICAL TRUE POSITIVE incident. The evidence confirms active exploitation of a known vulnerability in our environment that has not yet been patched. The attackers have successfully bypassed authentication and are attempting to establish persistence. This requires immediate emergency patching, system isolation, and incident response to prevent further compromise."
