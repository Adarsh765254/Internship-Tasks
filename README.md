# Cybersecurity Internship - Task 1

## Task 1 – Network Scanning and Analysis

### Description
This task focuses on performing basic network scanning and analyzing open ports to understand network security.

### Steps Completed

1. **Install Nmap**  
   Installed Nmap from the official website to perform network scanning.

2. **Find Local IP Range**  
   Determined the local network IP range (e.g., `192.168.1.0/24`).

3. **Run TCP SYN Scan**  
   Performed a TCP SYN scan using Nmap to detect active devices and open ports.

4. **Document Open Ports**  
   Recorded the IP addresses and open ports found during the scan.

5. **Optional Packet Analysis**  
   Analyzed captured network packets using Wireshark for deeper inspection.

6. **Service Research**  
   Researched common services running on the detected open ports.

7. **Security Assessment**  
   Identified potential security risks associated with the open ports.

8. **Save Results**  
   Exported and saved scan results in text and HTML formats for documentation.

### Files Uploaded
- Screenshots of the scans  
- PDF report of the analysis



# Cybersecurity Internship - Task 2

# Comprehensive Phishing Email Analysis Report

## Executive Summary

This report provides a detailed technical analysis of a phishing email titled "You Have [6] Unreceived Emails" from sender Al Bird <al.bird@consilio.com>. The analysis was conducted using multiple security tools including PhishTool, MXToolbox, and WHOIS lookup services. Critical findings show **SPF FAIL** and **DMARC FAIL** with only **DKIM PASS**, indicating significant authentication issues that are major red flags for potential phishing activity.

## Email Body Analysis

| Assessment Category | Status |
| Email is Poorly Written | ❌ NO |
| Creating the Sense of Urgency | ✅ YES |
| Asking You to Click on Link | ✅ YES |
| Impersonating Any Brand | ✅ YES |

## Sender Analysis

| Category | Status |
| Domain of the Sender is Authorized to Send Email | ❌ NO |
| Reputation of the Sender | ⚠️ SUSPICIOUS |
| Reputation of the IP | ⚠️ SUSPICIOUS |

## Header Analysis

| Protocol | Status | Impact |
| SPF | ❌ FAIL | CRITICAL |
| DKIM | ✅ PASS | LIMITED |
| DMARC | ❌ FAIL | CRITICAL |
| SCL | - | - |
| BCL | - | - |


## 1. Sender Email Address Analysis

### Primary Sender Information
- **Display Name**: Al Bird
- **Email Address**: al.bird@consilio.com
- **Domain**: consilio.com

### Spoofing Assessment - HIGH RISK

**CRITICAL AUTHENTICATION FAILURES DETECTED:**
- **SPF Status**: FAIL - Indicates the sending server is not authorized to send emails for this domain
- **DMARC Status**: FAIL - Domain's email authentication policy is not being met
- **Overall Assessment**: High probability of domain spoofing or compromised email infrastructure

### Spoofing Indicators
1. **Failed SPF Authentication**: The sending IP (18.184.203.244) is not authorized in the domain's SPF record
2. **DMARC Policy Violation**: The email fails the domain's authentication requirements
3. **Return-Path Mismatch Potential**: Authentication failures suggest potential path manipulation
4. **Generic Business Identity**: "consilio.com" could impersonate various legitimate consulting businesses

### Domain Analysis Red Flags
Authentication failures indicate either:
- Legitimate domain being spoofed by attackers
- Compromised legitimate email infrastructure
- Intentionally misconfigured domain for malicious purposes


## 2. Email Headers Technical Analysis

### Authentication Results - CRITICAL FAILURES

#### SPF (Sender Policy Framework)
- **Status**: FAIL
- **Significance**: The email originated from an unauthorized server
- **Security Impact**: HIGH - Major indicator of spoofing or compromised infrastructure
- **Technical Details**: Originating IP 18.184.203.244 not listed in domain's authorized senders

#### DKIM (DomainKeys Identified Mail)
- **Status**: PASS
- **Selector**: selector2-CONSILIO-US.onmicrosoft.com._domainkey
- **Algorithm**: rsa-sha256
- **Signing Domain**: CONSILIO-US.onmicrosoft.com
- **Note**: While DKIM passed, this only confirms message integrity, not sender legitimacy

#### DMARC (Domain-based Message Authentication)
- **Status**: FAIL
- **Policy Violation**: Email fails to meet domain's authentication requirements
- **Security Impact**: CRITICAL - Combined with SPF failure, indicates high phishing probability
- **DMARC Record**: `v=DMARC1; p=none; rua=mailto:consilio-t@dmarc.report-uri.com`

### Technical Infrastructure Analysis
- **Originating IP**: 18.184.203.244 (egress-ip21a.ess.de.barracuda.com)
- **Mail Route**: Complex routing through multiple Microsoft Exchange servers
- **Authentication Inconsistency**: DKIM pass with SPF/DMARC failures suggests sophisticated attack or infrastructure compromise

### Header Discrepancies
1. **Authentication Mismatch**: Conflicting authentication results indicate potential manipulation
2. **Complex Routing**: Multiple hops through different email systems
3. **Timestamp Consistency**: Headers show consistent timing (2022-08-08T18:29:00Z)
4. **Message-ID Format**: Legitimate Microsoft Exchange format but authentication failures raise concerns


## 3. Suspicious Links and Attachments Analysis

### HIGH-RISK URLs Identified

#### 1. Primary Suspicious URL:

https://afo3.digitaloceanspaces.com/zakwebsettsr979hoj0qp859/%26%21%24%21%26%20k%21%21%21%21/%24%21%24%21%24%26%26%20zK%20k%21%21%21.html#al.bird@consilio.com

- **Risk Level**: CRITICAL
- **Platform**: DigitalOcean Spaces (commonly abused by attackers)
- **Encoding**: Heavy URL encoding to obfuscate destination
- **Email Inclusion**: Contains sender's email address in URL fragment

#### 2. Secondary URL:

https://www.consilio.com/consilio-data-protection-notice/

- **Risk Level**: MODERATE
- **Purpose**: Appears to be privacy policy (could be legitimate or spoofed)

### Malicious Attachment Analysis
- **File**: phish_alert_sp2_2.0.0.0.eml (18.80 KB)
- **Type**: Email message file (.eml) - HIGH RISK
- **Threat Assessment**: Email attachments are common malware vectors
- **Hash Values for Forensic Analysis**:
  - **MD5**: `491563a5c2d01951dbeb007f6d3b60915`
  - **SHA-1**: `17e6dc3f9ec1e09f702ede8f6e5cf6f859581cb71`
  - **SHA-256**: `1e456f39ec78005c835222872b98cb373f9f925869a217adcadb8b220ff0ecc1`

### Link Analysis Summary
The combination of authentication failures and suspicious cloud storage URLs with encoded parameters represents a classic phishing attack vector designed to harvest credentials or deliver malware.


## 4. Urgent/Threatening Language Analysis

### Social Engineering Tactics

#### Manufactured Urgency:
- **Subject**: "You Have [6] Unreceived Emails" - Creates false urgency about missed communications
- **Body text**: "not delivered to Inbox" - Implies system malfunction requiring immediate action
- **Date specificity**: "5th August- 2022" - Adds credibility to false claim

#### Psychological Manipulation:
- **Fear of Missing Out**: Suggests important emails are being held
- **Authority Impersonation**: Presents as system notification from email provider
- **Solution Provision**: Offers immediate fix through potentially malicious action

#### Pressure Techniques:
- "Rectify Settings Below" - Direct call-to-action
- "Release Pending Message To Inbox" - Action button with urgent language
- "This was due to a system delay" - Technical explanation to build credibility

### Language Effectiveness Assessment
The email successfully creates a plausible technical scenario that would concern users about missing important communications, demonstrating sophisticated social engineering designed to bypass user skepticism.


## 5. URL Mismatch Analysis

### Critical Mismatches Identified

#### Button Text vs. Actual Destination:
- **Displayed Action**: "Release Pending Message To Inbox"
- **Actual URL**: Encoded DigitalOcean Spaces URL with suspicious parameters
- **Mismatch Severity**: CRITICAL - Complete disconnect between expected and actual destination

#### Domain Reputation Issues:
- **consilio.com**: Authentication failures indicate potential spoofing
- **digitaloceanspaces.com**: Legitimate service commonly abused by attackers
- **Encoded Parameters**: Obfuscated destination suggests malicious intent

### URL Structure Analysis
The heavily encoded URL structure with cloud storage hosting indicates:
1. Attempt to bypass security filters
2. Dynamic content generation for credential harvesting
3. Obfuscation to prevent easy analysis
4. Use of legitimate cloud services to appear trustworthy


## 6. Spelling and Grammar Assessment

### Language Quality Analysis
- **Grammar**: Professionally written with correct sentence structure
- **Spelling**: No obvious spelling errors detected
- **Formatting**: Clean, professional email template design
- **Technical Terms**: Appropriate use of email-related terminology

### Sophistication Indicators
- **High-Quality Presentation**: Professional formatting increases credibility
- **Legitimate Appearance**: Mimics genuine system notifications
- **Attention to Detail**: Careful construction suggests experienced attackers
- **Language Consistency**: Maintains professional tone throughout

The high quality of language and presentation makes this email particularly dangerous as it's more likely to bypass user suspicion compared to obviously poor-quality phishing attempts.


## 7. Comprehensive Phishing Traits Summary

### CRITICAL RED FLAGS IDENTIFIED

#### 1. Authentication Failures - CRITICAL
- **SPF FAIL**: Unauthorized sending server
- **DMARC FAIL**: Policy violation
- Combined failures indicate high phishing probability

#### 2. Suspicious URLs - HIGH RISK
- Cloud storage hosting with encoded parameters
- Complete mismatch between button text and destination
- Obfuscated URL structure

#### 3. Malicious Attachment - HIGH RISK
- .eml file from unknown sender
- Potential malware delivery vector
- Attachment size and type consistent with malicious payloads

#### 4. Social Engineering Techniques - SOPHISTICATED
- Manufactured urgency about undelivered emails
- False technical explanations
- Professional presentation to build trust

#### 5. Generic Targeting - MODERATE RISK
- "Dear User" greeting indicates mass targeting
- Lack of personalization typical of phishing campaigns

### THREAT ASSESSMENT: HIGH

**Overall Risk Level**: CRITICAL  
**Recommended Action**: IMMEDIATE DELETION AND REPORTING

### Authentication Summary
| Protocol | Status | Security Impact |
|----------|--------|-----------------|
| SPF | FAIL | Critical - Unauthorized sender |
| DKIM | PASS | Limited - Only confirms integrity |
| DMARC | FAIL | Critical - Policy violation |


## Conclusions and Incident Response Recommendations

### Immediate Actions Required

1. **DO NOT CLICK ANY LINKS** in this email
2. **DO NOT OPEN THE ATTACHMENT** - potential malware
3. **DELETE THE EMAIL** immediately
4. **REPORT TO IT SECURITY** team
5. **BLOCK SENDER DOMAIN** if not already blocked

### Security Assessment

This email represents a **sophisticated phishing attack** with multiple critical indicators:
- **Authentication failures** indicate compromised or spoofed domain
- **Malicious URLs** designed for credential theft or malware distribution
- **Professional presentation** designed to bypass user skepticism
- **Social engineering** creates false urgency to prompt quick action

### Long-term Security Measures

#### 1. Email Security Enhancement:
- Implement stricter DMARC policies
- Deploy advanced threat protection
- Regular security awareness training

#### 2. User Education:
- Train staff to recognize authentication warnings
- Emphasize importance of verifying unexpected emails
- Establish clear incident reporting procedures

#### 3. Technical Controls:
- Block cloud storage domains in email links
- Implement attachment sandboxing
- Deploy URL rewriting and analysis

### Forensic Information

#### Email Metadata:
- **Original timestamp**: 2022-08-08T18:29:00Z
- **Message-ID**: Complex Microsoft Exchange format
- **Attachment hashes**: Available for threat intelligence sharing
- **Originating IP**: 18.184.203.244 (compromised or malicious)


## Technical Appendix

### Analysis Tools Used
- **PhishTool**: Email header analysis and content inspection
- **MXToolbox**: DNS record verification and reputation checking
- **WHOIS Lookup**: Domain registration and ownership verification
- **Hash Analysis**: File integrity and malware detection

### Key Findings Summary
The combination of authentication failures (SPF FAIL, DMARC FAIL) with sophisticated social engineering and malicious URLs represents a high-priority security threat requiring immediate attention and organizational response.


## Final Assessment

**This email should be treated as a confirmed phishing attempt and handled according to security incident response procedures.**

### Risk Score: 🔴 CRITICAL (9.5/10)

### Confidence Level: 🔴 HIGH (95%)


## Usage Instructions

This README.md file contains the complete phishing email analysis report. To use this document:

1. **Copy the markdown content** for documentation purposes
2. **Share with security teams** for incident response
3. **Use for training purposes** to educate staff about phishing indicators
4. **Reference hash values** for threat intelligence sharing
5. **Implement recommended security measures** to prevent similar attacks

### Files Uploaded
- Screenshots of the scans  
- PDF report of the analysis

*Report generated using PhishTool, MXToolbox, and WHOIS analysis tools*  
*Date: Based on email timestamp 2022-08-08T18:29:00Z*

# Cybersecurity Internship - Task 3

# Nessus Vulnerability Assessment — Adarsh.lan (IP Address)

**Report:** Comprehensive Nessus Vulnerability Assessment Report  
**Target:** `IP Address` (Adarsh.lan)  
**OS:** Windows 11  
**Scanner:** Nessus Essentials 10.9.4  
**Scan Date:** 2025-09-25  
**Report Version:** 1.0  
**Classification:** Internal Use


## Table of Contents
- [Overview](#overview)
- [Scope & Objective](#scope--objective)
- [How to view the report files](#how-to-view-the-report-files)
- [Summary of Findings](#summary-of-findings)
- [Recommended Remediation (high level)](#recommended-remediation-high-level)
- [Detailed Remediation Steps (copy-pasteable commands)](#detailed-remediation-steps-copy-pasteable-commands)
- [Reproduce the Scan (steps)](#reproduce-the-scan-steps)
- [Notes & Limitations](#notes--limitations)
- [Next Steps & Roadmap](#next-steps--roadmap)
- [Contact](#contact)
- [Appendix: Files included](#appendix-files-included)


## Overview
This repository contains the README and pointers for the Nessus vulnerability assessment conducted against `adarsh.lan`IP Address). The attached full report (PDF) and any exported `.nessus`/`.nessusdb` exports contain complete scan details, screenshots, and plugin output.


## Scope & Objective
- **Scope:** Single host `IP Address` (Windows 11). Ports and services discovered by Nessus were analyzed.
- **Objective:** Identify vulnerabilities, categorize by severity, and recommend prioritized mitigations to reduce risk and meet basic compliance requirements.


## How to view the report files
Open the included files in the repository (if provided):
- `Nessus_Scan_Report.pdf` — human-readable executive summary + detailed findings (recommended for instructors/managers).
- `scan_export.nessus` — XML export of scan results (importable into another Nessus instance).
- `scan_export.nessusdb` — database export (for full history/metadata import).


## Summary of Findings
- **Total findings:** 45  
  - Medium: 7 (15.6%)  
  - Informational: 38 (84.4%)  
  - High/Critical: 0
- **Primary risk areas discovered:**
  - SSL/TLS certificate issues (self-signed, mismatched hostnames) on Splunk and Nessus management interfaces (ports 8089, 8191, 8834).
  - SMB signing not required (port 445).
  - Several informational exposures (service banners, versions, open ports such as 135, 139, 8000).


## Recommended Remediation (high level)
1. **Replace self-signed certificates** with CA-issued certificates (internal CA or public CA as appropriate). Ensure correct CN and SAN entries.
2. **Enable SMB signing** on Windows hosts to mitigate man-in-the-middle and tampering risks.
3. **Restrict access** to management interfaces (Splunk, Nessus) using firewall rules and network segmentation (management VLAN).
4. **Patch/update services** (e.g., upgrade Splunk to latest minor version).
5. **Implement certificate lifecycle management** (monitor expirations and automate renewals).
6. **Re-scan** after remediations and document results.


## Detailed Remediation Steps (copy-pasteable commands)

> **SSL/TLS** — Example PowerShell to create a properly SAN'd certificate (for testing/internal CA). Replace values and follow your CA process for production certificates:
```powershell
# Example: Create a self-signed cert with SANs (for lab/testing only)
$dnsNames = @("adarsh.lan","adarsh","IP Address")
New-SelfSignedCertificate -Subject "CN=adarsh.lan" -DnsName $dnsNames -NotAfter (Get-Date).AddYears(2) -KeyLength 2048 -CertStoreLocation cert:\LocalMachine\My

### Files Uploaded
- Screenshots of the scans  
- PDF report of the analysis


# **Cybersecurity Internship - Task 4**

## **Objective**
Demonstrate how to create, test, and remove firewall rules in Windows using the GUI and PowerShell, and understand how firewall filters traffic.

## **Steps Performed**

### 1. **Open Firewall Configuration Tool**
- Opened Windows Defender Firewall with Advanced Security (`wf.msc`).

### 2. **List Current Firewall Rules**
- Checked inbound rules in the GUI.
- Verified rules using PowerShell:
Get-NetFirewallRule

### 3. **Add Rule to Block Inbound Port 23 (Telnet)**
- GUI Steps:
  - Inbound Rules → New Rule → Port → TCP → 23 → Block → Domain/Private/Public → Name: BlockTelnet

### 4. **Test the Rule**
- PowerShell:
Test-NetConnection -ComputerName localhost -Port 23

- Output:
  - `PingSucceeded: True` → machine reachable
  - `TcpTestSucceeded: False` → port blocked by firewall

### 5. **Remove the Test Block Rule**
- GUI: Delete rule `BlockTelnet`
- PowerShell:
Remove-NetFirewallRule -DisplayName "BlockTelnet"

### 6. **Commands / GUI Steps Used**
| Task | Method / Command |
|------|----------------|
| List firewall rules | `Get-NetFirewallRule` |
| Create block rule (GUI) | Windows Firewall → Inbound Rules → New Rule → TCP 23 → Block → Domain/Private/Public → BlockTelnet |
| Test port | `Test-NetConnection -ComputerName localhost -Port 23` |
| Remove rule | `Remove-NetFirewallRule -DisplayName "BlockTelnet"` or GUI delete |

## **Summary**
- Firewall monitors inbound and outbound packets and filters based on rules.
- Blocked ports are denied, allowed ports are permitted.
- Default behavior: inbound mostly blocked, outbound mostly allowed.
- Custom rules give precise control over network access.

## **Conclusion**
- Created, tested, and removed firewall rules successfully.
- Demonstrated understanding of firewall operation and traffic filtering.
- Completed assignment safely without installing Telnet.

## **Files Uploaded**
- Screenshots of the scans
- PDF report of the analysis


# **Cybersecurity Internship - Task 5**

# Wireshark Packet Capture and Analysis

## Overview
This document summarizes the network traffic capture and analysis I performed using Wireshark. The task involved capturing packets on my active network interface, filtering protocols, and identifying different types of network communication.

## Tools Used
- **Wireshark** (Latest version installed)
- **Npcap** (for packet capturing on Windows)
- Web browser for generating traffic

## Steps Completed

1. **Wireshark Installation**
   - Successfully installed Wireshark along with Npcap on my Windows system.

2. **Captured Network Traffic**
   - Started capturing on the active network interface (Wi-Fi).
   - Generated traffic by visiting `http://neverssl.com`.

3. **Stopped Capture**
   - Stopped packet capture after 1 minutes of generating network traffic.

4. **Filtered Packets by Protocol**
   - Applied filters in Wireshark to analyze specific protocols:
     - `http` – For web requests
     - `dns` – For domain resolution
     - `tcp` – For transport layer communication

5. **Protocol Analysis**
   - **HTTP:** Observed GET and POST requests from the browser.
   - **DNS:** Captured queries and responses for domain name resolution.
   - **TCP:** Checked connection setup (SYN, SYN-ACK, ACK) and port usage.

6. **Packet Inspection**
   - Analyzed packet details including source IP, destination IP, ports, and payload information.
   - Noted patterns of communication and identified common services running on open ports.

7. **Saved Capture**
   - Saved the capture as `network_capture.pcap` for documentation and future reference.
   - Exported filtered packets as `.txt` for reporting purposes.

8. **Findings**
   - Identified multiple protocols in the captured traffic.
   - Observed normal web browsing traffic with no suspicious activity.
   - Confirmed the network was functioning as expected with HTTP, DNS, and TCP communications.


## Deliverables
- `network_capture.pcap` – Complete packet capture
- `filtered_packets.txt` – Exported filtered packet details
- Summary of protocol analysis and observations


## Notes
- Only one browser tab was active during capture to reduce noise.
- Wireshark was used safely, downloaded from the official website.


## **Files Uploaded**
- Screenshots of the scans
- PDF report of the analysis


# **Cybersecurity Internship - Task 6**

# Password Strength Analysis Project

A comprehensive study analyzing password security through systematic testing of various password combinations and complexity levels.

## Table of Contents

- [Overview](#overview)
- [Project Objectives](#project-objectives)
- [Methodology](#methodology)
- [Test Results](#test-results)
- [Key Findings](#key-findings)
- [Best Practices](#best-practices)
- [Common Attack Vectors](#common-attack-vectors)
- [Tools Used](#tools-used)

## Overview

This project demonstrates the critical importance of password complexity in cybersecurity through practical testing and analysis. Eight different passwords were evaluated using password strength checking tools to understand how length, character diversity, and patterns affect overall security.

## Project Objectives

1. Create multiple test passwords with varying complexity levels
2. Evaluate passwords using character type combinations (uppercase, lowercase, numbers, symbols)
3. Test passwords using online strength checkers
4. Document scores and feedback from security tools
5. Identify and document best practices for password creation
6. Research common password attack methodologies
7. Analyze the relationship between complexity and security
8. Provide actionable recommendations for users

## Methodology

### Test Passwords

Eight passwords were created representing different security levels:

| Password | Length | Character Types | Complexity Level |
|----------|--------|-----------------|------------------|
| `raj1` | 4 | Lowercase, Numbers | Very Weak |
| `raj12` | 5 | Lowercase, Numbers | Weak |
| `raj1234` | 7 | Lowercase, Numbers | Weak |
| `raj1234567` | 10 | Lowercase, Numbers | Moderate |
| `Raj@$125` | 8 | Mixed (all types) | Strong |
| `R@j3$H!92#LmX&` | 14 | Mixed (all types) | Very Strong |
| `Rajesh` | 6 | Upper, Lowercase | Weak |
| `Rajesh@754$` | 11 | Mixed (all types) | Strong |

### Testing Approach

- Each password was evaluated using password strength checking tools
- Metrics collected: estimated crack time, strength score, vulnerability warnings
- Analysis focused on: length impact, character diversity, pattern recognition
- Comparative analysis between similar passwords with minor variations

## Test Results

### Key Observations

**Length Impact:**
- 4-character passwords: Crackable in < 1 second
- 8-character passwords (mixed): 7+ years to crack
- 12+ character passwords: Centuries to crack

**Character Diversity Impact:**
- Lowercase only: Minimal security regardless of length
- Adding uppercase: 2x security improvement
- Adding numbers: 2.4x security improvement
- Adding symbols: 1.5x security improvement
- **Combined effect**: 7.2x security improvement

**Pattern Recognition:**
- Sequential numbers (123456): Instantly crackable
- Dictionary words (Rajesh): Highly vulnerable to dictionary attacks
- Name-based passwords: Susceptible to social engineering

## Key Findings

### Critical Success Factors

1. **Length is paramount**: Each additional character exponentially increases security
2. **Character diversity matters**: Using all four character types (upper, lower, number, symbol) provides significant protection
3. **Avoid patterns**: Sequential or predictable patterns dramatically reduce security
4. **Dictionary words are dangerous**: Common words and names are easily cracked
5. **Uniqueness is essential**: Reusing passwords across accounts multiplies risk

### Security Equation

Security = (Character Pool Size)^Length × Pattern Randomness

### Crack Time Comparison

| Password Type | 8 Characters | 12 Characters | 16 Characters |
|---------------|--------------|---------------|---------------|
| Lowercase only | 7 hours | 2 months | 5 years |
| All char types | 7 years | 34,000 years | 44 million years |

## Best Practices

### Password Creation Standards

**Minimum Requirements:**
- ✅ 12+ characters minimum
- ✅ At least one uppercase letter (A-Z)
- ✅ At least one lowercase letter (a-z)
- ✅ At least one number (0-9)
- ✅ At least one special symbol (@, #, $, !, etc.)
- ✅ No dictionary words or common names
- ✅ No sequential patterns or repeated characters
- ✅ Unique password for each account

### Recommended Strategies

1. **Use Password Managers**: LastPass, 1Password, Bitwarden
2. **Enable Two-Factor Authentication (2FA)**: Add extra security layer
3. **Regular Updates**: Change passwords every 90-180 days for critical accounts
4. **Passphrase Method**: Combine random words with symbols ("Coffee$Morning#Beach!2024")
5. **Acronym Method**: Create from sentences ("IW2EbCo@8AM!" = I Wake 2 Eat breakfast Coffee @ 8 AM!)

## Common Attack Vectors

### 1. Brute Force Attack
- **Method**: Systematically tries every possible character combination
- **Defense**: Use 12+ character passwords with mixed types

### 2. Dictionary Attack
- **Method**: Uses pre-compiled lists of common words and passwords
- **Defense**: Avoid dictionary words, names, and common phrases

### 3. Rainbow Table Attack
- **Method**: Uses pre-computed hash tables to reverse password hashes
- **Defense**: Proper salting and modern hashing algorithms (bcrypt, Argon2)

### 4. Credential Stuffing
- **Method**: Uses stolen credentials from data breaches
- **Defense**: Unique passwords for each account, breach monitoring

### 5. Phishing
- **Method**: Social engineering to trick users into revealing passwords
- **Defense**: Verify URLs, never click email links, enable 2FA

### 6. Keylogger
- **Method**: Malware records keystrokes
- **Defense**: Anti-malware software, password managers with auto-fill

## Tools Used

- **Password Strength Checkers**: Online security analysis tools
- **Documentation**: Microsoft Word


## Key Takeaways

1. **Length beats complexity**: A longer simple password is better than a short complex one
2. **Complexity multiplies security**: Combining all character types creates exponential improvement
3. **Patterns are deadly**: Any predictable pattern reduces security to near zero
4. **Uniqueness is critical**: Password reuse is the most common security failure
5. **Tools are essential**: Password managers enable maximum security without memorization burden


## **Files Uploaded**
- Screenshots of the scans
- PDF report of the analysis


# **Cybersecurity Internship - Task 7**

# Browser Extension Management and Performance Analysis

## Overview

This project documents an exercise focused on understanding browser extensions, their impact on performance, and the potential threats posed by malicious extensions. The process involved managing extensions, conducting performance benchmarks, and researching security implications.

## Project Objectives

1.  Learn to spot and remove potentially harmful browser extensions.
2.  Understand the impact of extensions on browser performance.
3.  Research and document how malicious extensions can harm users.

## Tools Used

*   Google Chrome (or any modern web browser)
*   Speedometer 2.1 (web browser benchmark tool)

## Project Deliverables

*   Documentation of steps taken to manage extensions.
*   Performance benchmark results (before and after extension removal).
*   Research on how malicious extensions can harm users.

## Steps Taken and Findings

### Part 1: Extension Management and Performance Testing

1.  **Open your browser’s extension/add-ons manager.**
    *   Accessed Google Chrome's extension management page (`chrome://extensions/`).

2.  **Review all installed extensions carefully.**
    *   Conducted a review of all currently active extensions within the browser.

3.  **Check permissions and reviews for each extension.**
    *   Inspected the permissions requested by extensions and briefly checked user reviews where applicable to identify any suspicious behavior or unnecessary access.

4.  **Identify any unused or suspicious extensions.**
    *   For the purpose of this exercise, the "Google Keep" extension was used as a benign example of an extension that could be added and then removed to observe performance impact.

5.  **Remove suspicious or unnecessary extensions.**
    *   The "Google Keep" extension was first installed (simulating an addition) and then subsequently removed as per the exercise's objective to manage extensions.

6.  **Restart browser and check for performance improvements.**
    *   The browser was restarted after the removal of the "Google Keep" extension.
    *   **Performance Benchmark (Speedometer 2.1) Results:**
        *   **With Google Keep installed:** `303 ± 15 (4.9%) runs/min`
        *   **Without Google Keep installed:** `313 ± 14 (4.5%) runs/min`
    *   **Observation:** A minor but measurable performance improvement was noted (an increase of 10 runs/min). This demonstrates that even safe and seemingly light extensions can consume resources and impact browser speed. Regularly reviewing and removing unused extensions can contribute to better performance.

### Part 2: Research and Documentation

7.  **Research how malicious extensions can harm users.**

    Malicious browser extensions are a significant threat vector, often operating under the guise of legitimate tools. They can cause various harms:

    *   **Data Theft and Privacy Invasion:**
        *   **Tracking:** Monitor browsing activity, search queries, and online interactions.
        *   **Credential Harvesting:** Employ keyloggers or fake forms to steal sensitive login credentials (e.g., banking, email, social media).
        *   **Personal Data Access:** Access browser history, cookies, autofill data, and potentially data from other extensions.
        *   **Adware & Pop-ups:** Inject unwanted advertisements, redirect to malicious sites, and generate intrusive pop-ups, often leading to further scams.

    *   **Security Vulnerabilities:**
        *   **Malware Distribution:** Act as a conduit to download and install other malware (e.g., viruses, ransomware, spyware).
        *   **Phishing:** Alter legitimate webpages or inject content to trick users into revealing sensitive information.
        *   **Cross-Site Scripting (XSS):** Exploit vulnerabilities to execute malicious scripts, leading to session hijacking or data manipulation.

    *   **Performance Degradation and Browser Hijacking:**
        *   **Slow Performance:** Consume significant system resources (CPU, RAM), causing the browser to slow down, crash, or become unresponsive.
        *   **Browser Hijacking:** Change default browser settings (homepage, search engine, new tab page) without consent, redirecting traffic to attacker-controlled sites.
        *   **Resource Exploitation:** Secretly use the user's computer for illicit activities like cryptocurrency mining or click fraud, increasing power consumption and degrading system performance.

8.  **Document steps taken and extensions removed.**

    *   **Documented Steps:** All steps from 1 to 7, including observations and research findings, have been documented in this `README.md` file.
    *   **Extensions Involved (for demonstration):**
        *   **Google Keep:** Installed temporarily for performance testing, then removed. (Note: Google Keep itself is a legitimate and safe extension, used here purely for the exercise's practical demonstration.)

## Conclusion

This exercise highlights the importance of regularly auditing installed browser extensions. Even seemingly harmless extensions can impact performance, and vigilance is crucial to prevent the installation of malicious ones that can severely compromise privacy, security, and system integrity. Always review an extension's permissions and user reviews before installation.

## **Files Uploaded**
- Screenshots of the scans
- PDF report of the analysis

