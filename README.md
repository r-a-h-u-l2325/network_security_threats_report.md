# network_security_threats_report.md

Objective- Write a comprehensive research report on common network security threats such as DoS attacks, Man-in-the-Middle (MITM) attacks, and spoofing.

1) DoS Attack
A Denial of Service(DoS) attack is a malicious effort to bring down the normal operation of an intended server,service or a network by overloading it with an avalanche of internet traffic.These kinds of attacks are meant to make the system unavailable to its intended users,causing it to be down,slow or shut down completely.The main intention of a DoS attack is to deny access to valid users.

Working of DoS attack
1) The attacker sends a massive number of requests or data packets to a target system.
2) The system becomes overloaded with processing these fake requests.
3) Legitimate user requests cannot be processed,causing a denial of service.

Impact of DoS attack
1) Service Downtime- A DoS attack can render websites,applications,or entire networks inaccessible to legitimate users,directly affecting business operations.
2) Financial Loss- Downtime leads to lost revenue,especially for e-commerce platforms,SaaS providers, and financial institutions that rely on constant uptime.
3) Reputations Damage- Repeated outages can erode customer trust and damage the organization's brand image.
4) Security Diversions- DoS attacks are often used as a smokescreen to distract IT teams while more sophesticated breaches are carried out.
5) Resource Drain- Excessive consumption of CPU,memory,and bandwidth can affect not just the targeted system,but also other dependent services.

Mitigation Strategies
1) Traffic Filtering- Configure firewalls,intrusion prevention system(IPS),and load balancers to detect and drop abnormal traffic spikes and limit repeated request.
2) Web Application Firewalls(WAFs)- Deploy WAFs to filter malicious HTTP traffic and protect against application-layer DoS attempts.
3) Network Redundancy- Design your network with redundant paths,servers,and ISPs to prevent a single point of failure.
4) Real-Time Monitoring and Alerts- Implement continuous traffic monitoring and alert systems to detect anamalies early and respond swiftly.
5) Incident Response Planning- Maintain a documented and tested DoS response plan that includes escalation procedures,roles,and communication stategies.


2) Man-In-The-Middle(MITM) Attack
A MITM Attack is a form of cyber attack in which an attacker surreptitiously intercepts and possibly manipulates the communication between two parties that think they are communicating directly with one another.
Suppose two individuals are talking by mail,and a third individual intercepts,reads,andsometimes alters those mail before presenting them.This is precisely what a MITM
attack does in the cyber world.

Working of MITM Attack
1) Interception- The attacker positions themselves between two legitimate parties to eavesdrop on their communication.This can be done through the following ways:-
                 ARP Spoofing: sending fake ARP messages to redirect traffic through the attacker's machine.
                 DNS Spoofing: redirecting a user to a fake website instead of the real one.
                 Wi-Fi Eavesdropping: setting up rogue access points to trap users into unsafe connections.

2) Decryptiom- If the communication is encrypted,the attacker might use the SSL stripping to downgrade HTTPS to HTTP or Present a fake certificate to intercept SSL/TLS traffic.

3) Data Manipulation- The attackers may steal credentials(usernames,passwords,credit card information),inject malicious content(malware,fake login pages) or modify transactions or
                      communications.

Impact of MITM Attacks
1) Loss of Confidentiality: sensitive data like passwords,emails and financial details can be leaked.
2) Identity Theft: Attackers may impersonate users to access confidential systems.
3) Financial Fraud: Bank tranfers or payment details can be intercepted and altered.
4) Reputation Damage: Organizations may suffer a loss of customer trust.
5) Regulatory Penalties: Failure to protect user data can result in legal consequences.

Mitigation Strategies
1) End-to-End Encryption- Always prefer HTTPS over HTTP and implement TLS 1.2 or higher for secure connections.
2) Secure Wi-Fi Networks- Avoid public Wi-Fi or use VPNs when connected to unsecured networks and ensure WPA3 encryption on personal and enterprise Wi-Fi.
3) Employ Network Security Tools- Use Intrusion Detection System(IDS) and Intrusion Prevention System(IPS) to monitor unusual activity and deploy firewalls and packet filtering to block                                    suspicious traffic.
4) Awareness and Training- Educate users to identify suspicious websites and avoid clicking on suspicious links.
5) Regular Updates and Patch Management- Keep all systems and software up-to-date to fix known vulnerabilities.


3) Phishing Attack
A Phishing attack is a social engineering method in which cyber thugs deceive people into disclosing confidential information,like login credentials,bank data or personal identity information by posing as a credible source.Phishing is generally conducted through fake emails,messages,web sites or calls mimicking legitimate institutions such as banks,government authorities or popular web sites.

Working of Phishing Attack
1) The attacker crafts a fake but convincing message imporsonating a trusted entity.
   Ex:- Your account has been compromised click here to reset your password.
2) The message is sent out to thousands of users or targeted individuals.
3) The victim clicks a malicious link or opens an infected attachment,which redirects them to a fraudulent website or triggers malware download.
4) The fake website or form collects credentials or sensitive data,which is then sent back to the attacker.
5) Once the attacker has the stolen data,they can Access accounts,commit fraud or identity theft ,spread malware to other systems.

Impact of Phishing Attack
1) Credential Theft- Usernames,passwords,and PINs are compromised.
2) Financial Loss- Unauthorized transactions,bank fraud, and credit card misuse.
3) Identity Theft- Stolen personal information can be used to impersonate the victim.
4) Corporate Espionage- In spear phishing attackers steal business-critical data or gain unauthorized access to enterprise systems.
5) Reoutational Damage- Organizations that fall victim to phishing may lose customer trust and face legal liabilities.

Mitigation Strategies
1) Email Security Measures- Use anti-phishing filters and spam blockers.It enable email authentication protocols like SPF,DKIM, and DMARC to validate legitimate senders.
2) Verify Link Before Clicking- Hover over links to check the actual URL.Avoid clicking on suspicious or unexpected email links.
3) Use Multi-Factor Authentication(MFA)-Even if a password is stolen,MFA provides an additional security layer.
4) User Awareness and Training- Conduct Phishing simulations and security measures training for employees and users.Educate users to recognize red flags like urgent language,typos,or unfamiliar senders.
5) Keep Software and Systems Updated- Patch browser vulnerabilities and email client flaws.Use the latest version of antivirus and endpoint protection tools.


4) Malware(viruses,worms,trojans,ransomware,spyware) Attack
Malware is a general class of software purposefully designed to harm,disrupt, or to attain unauthorized access to computer systems,networks, or data.It runs in stealth mode and tends to inflict serious damage unbeknownst to the user.

Working of Malware Attack
1) Viruses: A virus attaches itself to a legitimate file or program and spreads when that file is executed.It often replicates and inserts itself into other files.
2) Worms: Worms are self-replicating programs that spread across networks without user intervention.They exploit vulnerabilities in network protocols or software.
3) Trojans: A trojan disguises itself as legitimate software or hides within useful applications.Once installed,it opens a backdoor for attackers.
4) Ransomware: Ransomware encrypts the victim's data and demands a ransom in cryptocurrency to restore access.
5) Spyware: Spyware secretly monitors user activity and collects sensitive information like keystrokes,login credentials or browsing history.

Impact of Malware Attacks
1) Data Loss- Files may be deleted,corrupted,or encrypted beyond recovery.
2) Financial Loss- Ransom demands,system repairs,legal penalties, and reputational, damage.
3) Privacy Breach- Theft of personal,financial,or confidential business information.
4) System Disruption- Slow performance,frequent crashes, or complete system failure.
5) Network Compromise- Malware can spread across an organization's entire network,infecting multiple systems.


Mitigations Strategies
1) Use Reputable Antivirus and Anti-Malware Software- Keep it updated and run regular scans to detect and eliminate threats.
2) Apply Software and OS Updates promptly- Patch known vulnerabilities that malware might exploit.
3) Enable Firewalls- Use both network and host-based firewalls to monitor and control incoming/outgoing traffic.
4) Educate Users- Conduct cybersecurity awareness training to prevent phishing,suspicious downloads and social engineering.
5) Backup Data Regularly- Use offline or cloud backups to ensure data can be restored if attacked by ransomware.


5) SQL Injection
SQL Injection is a form of cyber attack where an attacker injects evil SQL code into input fields of a web application in order to control the backend database.It takes advantage of weaknesses in the application's input validation and query execution process.

Working of SQL Injection
1) Web applications that use SQL databases(e.g.,MySQL,Oracle,SQL Server).
2) Occurs when user inputs are directly included in SQL queries without proper sanitization or validation.
3) Forms,URL parameteres,cookies, or HTTP headers.


Impacts of SQL Injection
1) Unauthorized Access- Attackers can log in as admins or users without credentials.
2) Data Theft or Leakage- Personal,financial or confidential business information can be extracted.
3) Data Manipulation or Deletion-Attackers can modify ,insert,or delete data in the database.
4) Reputation Damage-Breaches can lead to loss of customer trust,legal penalties, and financial losses.
5) Remote Command Execution- Attackers may escalate to execute system-level commands on the host machine.


Mitigation Strategies
1) Use Prepared Statements- Ensure user input is treated strictly as data,not executable code.
2) Input Validation and Sanitization- Accepts only expected formats(e.g.,alphanumeric for usernames).
                                      Reject or sanitize special characters like ',;,--,etc.
3) Least Privilege Principle-Database accounts used by applications should have minimal permissions(e.g.,no DROP TABLE privilege).
4) Web Application Firewalls(WAFs)-Deploy WAFs to detect and block malicious query patterns before they reach the server.
5) Error Handling- Avoid displaying detailed error messages.These can reveal database structure and help attackers craft their payloads.


6) Zero-Day Exploits
A Zero-Day Exploits is a cyber attack that targets a software vulnerability unknown to the software vendor or security community.The term "zero-day" refers to the fact that developers have had zero days to fix the flaw before it is exploited.

Working of Zero-Day Exploit Attack
1) A hacker discovers a previously unknown vulnerability in an application,operating system,browser,or device.
2) The attacker develops an exploit-malicious code or payload that leverages the vulnerability.
3) The exploit is deployed before the vendor becomes aware and before a patch is issued.
4) Often delivered via phishing emails,malicious downloads,compromised websites,or drive-by attacks.
5) Once the exploit is triggered,it can install malware,steal data,or gain remote control.


Impact of Zero-Day Exploit Attack
1) Unauthorized Access- Attackers may gain control over systems without detection.
2) Malware Deployment- Zero-day vulnerabilities are often used to install ransomware,spyware or keyloggers.
3) Data Breaches- Sensitive Information such as login credentials,financial data, or intellectual property may be stolen.
4) Financial and Reputational Damage-Organizations may suffer brand damage,lawsuits,compliance violations, and significant recovery costs.
5) Detection Difficulty- Since the vulnerability is unknown,traditional security tools like antivirus or firewalls may not detect it.


Mitigation Strategies
1) Patch Management and Virtual Patching- Apply updates and security patches as soon as they are released.Use virtual patching via intrusion prevention system(IPS) to protect vulnerable                                           systems temporarily.
2) Threat Intelligence Services- Suscribe to real-time threat intelligence feeds to stay informed about emerging exploits.Use security information and event management(SIEM) to                                           correlate and detect anomalies.
3) Behavior-Based Detection- Use advanced endpoint protection(EPP) and endpoint detection and response(EDR) solutions that analyze behavior,not just known signatures.
4) Zero Trust Architecture- Trust no device or user by default;enforce identity verification and least-priviledge access to all resources.
5) Incident Response Plan-Prepare and test an incident response plan for rapid containment,investigation,and recovery.


7) Password Attacks
A Password Attack is a method used by cyber criminals to gain unauthorized access to user accounts,systems or network by cracking or guessing login credentials.These attacks are common because passwords are often the weakest link in an organization's security.

Working of Password Attacks
1) Brute Force- The attacker systematically tries every possible combination of characters until the correct password is found.
2) Dictionary- The attacker uses a precompiled list of commonly used passwords instead of all combinations.
3) Credential Stuffing- Attackers use username-password pairs stolen from other data breaches and try them across multiple websites.


Impact of Password Attcks
1) Unauthorized Access- Attackers can gain entry to sensitive systems,emails,databases, or cloud services.
2) Data Theft or Leakage- Accessed accounts may contain confidential personal,financial or business information.
3) Financial Fraud- Compromised credentials for banking or payment platforms can lead to theft.
4) Identity Theft- Personal accounts can be used to impersonate victims or launch further attacks.
5) Reputational and Legal Consequenes- Organizations may suffer from public trust loss and may face data protection violations.


Mitigation Strategies
1) Enforcing Strong Password Policies- Require passwords to be long,complex, and not easily guessable and also Avoid common passwords and encourage passphrases.
2) Enable Multi-Factor Authentication(MFA)-Add an extra layer of protection beyond the password.Even if a password is compromised,access is denied without the second factor.
3) Use Password Hashing and Salting- Store passwords as hashed values.Add a unique salt to each password to prevent attackers from using precomputed hash databases.
4) Implement Credential Stuffing Protection- Monitor for unusual login patterns or mass login attempts from the same IP.Use bot protection systems and behavioral analytics.
5) Monitor for Credential Leaks- Use threat intelligence and dark web monitoring to identify leaked credentials associated with your domain.
