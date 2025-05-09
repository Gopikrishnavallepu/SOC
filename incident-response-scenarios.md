# SOC Incident Response Scenarios

## Scenario 1: Phishing Campaign Detection

**Alert Received:**
Your Proofpoint email security solution has flagged multiple suspicious emails with similar patterns being delivered to executives, with Secureworks XDR correlating this with unusual authentication attempts.

**Your Response:**

1. **Initial Triage:**
   "Upon receiving the correlated alert from Proofpoint and Secureworks XDR, I immediately initiated our phishing incident response protocol. I verified the scope by checking if the campaign targeted specific departments or roles, discovering it primarily focused on our executive team."

2. **Analysis:**
   "I extracted the suspicious emails to our analysis environment and examined their characteristics - identifying sophisticated spear-phishing tactics with company-specific information. The emails contained a PDF attachment that exploited a zero-day vulnerability attempting to establish a C2 connection."

3. **Containment:**
   "I implemented immediate containment measures by:
   - Working with our email team to create a custom rule in Proofpoint to quarantine all similar messages
   - Using Crowdstrike Falcon to deploy an emergency prevention policy to block the specific malware signatures
   - Directing Zscaler to block the identified command and control domains"

4. **Communication:**
   "I promptly notified our security leadership and initiated our executive communication protocol. I provided clear, non-technical guidance to potential recipients about identifying these specific emails and proper reporting procedures."

5. **Remediation:**
   "For potentially affected systems, I deployed Crowdstrike's Real-Time Response capabilities to isolate affected endpoints and remove malicious artifacts. I worked with our vulnerability management team to fast-track patching for the exploited vulnerability across the environment."

6. **Lessons Learned:**
   "Following the incident, I led a post-mortem analysis that resulted in enhancing our detection rules, implementing additional security awareness training for executives, and improving our phishing simulation program to include similar tactics."

## Scenario 2: Advanced Persistent Threat (APT) Detection

**Alert Received:**
Crowdstrike Falcon has detected unusual PowerShell activity on several servers, while GuardDuty has identified suspicious API calls accessing sensitive S3 buckets from unusual locations.

**Your Response:**

1. **Initial Assessment:**
   "After receiving these correlated alerts, I immediately recognized potential APT activity based on the sophisticated techniques involved. I established an incident war room and assembled our Tier 3 analysis team and incident responders."

2. **Investigation:**
   "I led a comprehensive investigation leveraging:
   - Secureworks XDR to correlate events across our environment
   - Crowdstrike's process tree analysis to trace the PowerShell execution chain
   - CloudTrail logs to track all API activities associated with the affected resources
   - Endpoint memory analysis to identify potential rootkits or advanced implants"

3. **Threat Hunting:**
   "I initiated parallel threat hunting activities focused on:
   - Identifying all potentially compromised systems using similar IOCs
   - Analyzing lateral movement attempts through our environment
   - Reviewing privileged account usage for signs of credential theft
   - Examining data exfiltration attempts through our Zscaler logs"

4. **Containment Strategy:**
   "Given the sophistication of the threat, I implemented a carefully sequenced containment strategy:
   - First isolating non-critical affected systems via Crowdstrike network containment
   - Implementing temporary conditional access policies through our IAM systems
   - Creating custom Zscaler rules to block communication with identified C2 infrastructure
   - Placing critical systems under enhanced monitoring while preparing for coordinated remediation"

5. **Executive Communication:**
   "I provided regular briefings to our CISO and executive team, including:
   - Current assessment of the threat actor and their capabilities
   - Potential business impact and data exposure risk
   - Containment and remediation timelines
   - Regulatory reporting obligations"

6. **Recovery and Hardening:**
   "After containing the threat, I oversaw:
   - Forensic preservation of evidence for potential legal proceedings
   - Complete rebuild of compromised systems from trusted images
   - Implementation of additional security controls to prevent similar attacks
   - Development of custom detection rules in our XDR platform based on the attack techniques observed"

## Scenario 3: Critical Vulnerability Exploitation

**Alert Received:**
Tenable Nessus has identified a critical vulnerability in your web application framework, and shortly after, Secureworks XDR detects exploitation attempts against your internet-facing applications.

**Your Response:**

1. **Rapid Vulnerability Assessment:**
   "Upon receiving the Nessus alert, I immediately performed a rapid impact assessment to:
   - Identify all affected systems across our environment
   - Determine potential exploit scenarios and business impact
   - Prioritize systems based on exposure and criticality"

2. **Exploitation Monitoring:**
   "When Secureworks XDR detected active exploitation attempts, I:
   - Analyzed the attack patterns to understand the specific exploit methods
   - Verified if any attempts had been successful by examining application logs
   - Deployed custom IDS signatures to detect the specific exploitation patterns"

3. **Emergency Patching Protocol:**
   "I activated our emergency patching protocol, including:
   - Deploying available patches to development environments for rapid testing
   - Implementing virtual patching through Zscaler and web application firewalls
   - Coordinating with application teams for emergency maintenance windows
   - Establishing continuous vulnerability scanning to verify patch effectiveness"

4. **Compensating Controls:**
   "For systems that couldn't be immediately patched, I implemented compensating controls:
   - Using Crowdstrike's application control features to prevent unauthorized code execution
   - Configuring additional monitoring alerts specific to potential exploitation indicators
   - Implementing network segmentation to limit potential lateral movement"

5. **Verification and Follow-up:**
   "After remediation activities, I:
   - Conducted penetration testing to verify the vulnerability was properly addressed
   - Performed a root cause analysis of how the vulnerability was introduced
   - Updated our secure development practices to prevent similar issues
   - Added the exploitation technique to our red team scenarios"

## Scenario 4: Insider Threat Detection

**Alert Received:**
Secureworks XDR has correlated unusual data access patterns from an employee account, accessing sensitive documents outside normal working hours and attempting to exfiltrate data.

**Your Response:**

1. **Careful Initial Handling:**
   "Given the sensitive nature of potential insider threats, I:
   - Consulted our insider threat response protocol which requires HR and Legal involvement
   - Gathered preliminary evidence while maintaining strict confidentiality
   - Documented all investigative steps with appropriate chain of custody"

2. **Evidence Collection:**
   "Working with authorized stakeholders, I:
   - Used Crowdstrike to capture forensic timeline data from the employee's endpoint
   - Analyzed Zscaler logs to identify attempted data transfers
   - Reviewed CloudTrail logs for sensitive resource access
   - Examined email logs for external communications containing sensitive content"

3. **Risk Assessment:**
   "Based on the evidence, I provided leadership with:
   - An assessment of what data may have been compromised
   - Potential business impact and exposure risk
   - Recommendations for immediate containment actions
   - Legal and regulatory considerations"

4. **Coordinated Response:**
   "After receiving proper authorization, I implemented:
   - Account access restrictions while maintaining system integrity
   - Enhanced monitoring of the user's activities
   - Preservation of forensic evidence for potential legal proceedings
   - Discrete containment actions to prevent data loss while the investigation continued"

5. **Remediation and Improvement:**
   "Following resolution of the incident, I:
   - Worked with data owners to assess actual data exposure
   - Recommended improvements to our DLP policies based on findings
   - Enhanced our insider threat monitoring capabilities
   - Provided input for updated security awareness training"

## Scenario 5: Ransomware Attack Response

**Alert Received:**
Multiple Crowdstrike alerts show signs of encryption activities across several endpoints, with rapid file modifications and suspicious processes that indicate a ransomware attack in progress.

**Your Response:**

1. **Immediate Containment:**
   "Upon confirmation of ransomware activity, I:
   - Immediately activated our ransomware response playbook
   - Used Crowdstrike's network containment feature to isolate affected endpoints
   - Directed the network team to implement emergency network segmentation
   - Shut down critical file shares to prevent further encryption"

2. **Attack Scope Assessment:**
   "To understand the attack scope, I:
   - Used Secureworks XDR to identify patient zero and infection vector
   - Mapped the lateral movement path through our environment
   - Determined which systems and data were already affected
   - Identified the specific ransomware variant through malware analysis"

3. **Critical Service Preservation:**
   "To maintain business operations, I:
   - Worked with business units to prioritize critical systems for protection
   - Implemented additional protections for essential services
   - Coordinated with the disaster recovery team to prepare for potential restoration
   - Established alternative communication channels if needed"

4. **Executive and Stakeholder Communication:**
   "I provided leadership with:
   - Regular status updates on the attack progression and containment
   - Clear assessment of business impact and recovery timeline
   - Options for response, including restoration approaches
   - Guidance on potential regulatory and customer notification requirements"

5. **Recovery Execution:**
   "After containing the attack, I coordinated:
   - Systematic restoration from backups in order of business priority
   - Verification of system integrity before reconnection
   - Implementation of additional security controls to prevent reinfection
   - Post-incident monitoring to detect any persistent malware"

6. **Post-Incident Activities:**
   "Following the incident, I led:
   - A comprehensive analysis of how the attack succeeded
   - Implementation of security improvements based on findings
   - Enhancement of our detection capabilities to identify similar attacks earlier
   - Updates to our incident response playbooks based on lessons learned"

## Communication Templates for Common Scenarios

### 1. Suspicious Email Notification to Employees

"SECURITY ALERT: Our security team has identified a targeted phishing campaign affecting Company X. These emails appear to come from HR with the subject 'Urgent: Benefit Changes Required' and ask you to click a link to verify your information.

DO NOT click any links or open attachments in these emails. If you have received this email, please report it immediately using the Phish Alert button in Outlook. If you have clicked any links or entered credentials, please contact the Security team immediately at security@companyx.com or x5555.

Our team is actively blocking these messages, but some may have reached inboxes before detection."

### 2. Security Incident Update to Leadership

"Executive Security Briefing: Ransomware Incident Status #3

Current Status: CONTAINED - Remediation in Progress
Incident Timeline: Initial detection at 02:14 on April 1, 2025. Containment achieved at 03:45.

Impact Assessment:
- 37 endpoints affected (4% of environment)
- Finance file server partially encrypted
- No evidence of data exfiltration based on current analysis
- No impact to production systems or customer-facing services

Actions Completed:
- Source identified as compromised vendor account
- All affected systems isolated
- Backup restoration process initiated for finance server
- Enhanced monitoring deployed across environment

Next Steps:
- Complete restoration of affected systems (ETC: 14:00 today)
- Reset all vendor account credentials and implement MFA
- Conduct full sweep for indicators of compromise
- Prepare customer and regulatory communications if needed

Business Continuity:
Finance team operating with limited capacity - workarounds in place. All other departments operating normally.

Next update scheduled for 12:00 or sooner if significant developments occur."

### 3. True Positive Alert Handling Process

"When handling confirmed true positive security alerts, I follow this structured approach:

1. Alert Verification and Enrichment:
   - Confirm alert is legitimate through multiple data sources
   - Gather context (affected systems, users, data)
   - Determine initial severity based on our classification matrix

2. Documentation Initiation:
   - Create incident ticket with initial findings
   - Document timestamp, alert sources, and initial assessment
   - Link to relevant playbooks and procedures

3. Containment Decision:
   - Evaluate containment options based on threat type and business impact
   - Select appropriate containment approach (monitor, partial containment, full isolation)
   - Implement containment measures using appropriate tools (Crowdstrike, Zscaler, etc.)

4. Stakeholder Notification:
   - Notify appropriate teams based on incident type and severity
   - Provide clear, actionable information relevant to each stakeholder
   - Establish communication cadence for updates

5. Investigation and Remediation:
   - Perform root cause analysis
   - Identify and implement required remediation steps
   - Verify remediation effectiveness through testing

6. Continuous Improvement:
   - Update detection rules based on findings
   - Enhance playbooks with lessons learned
   - Share sanitized information with security community when appropriate"
