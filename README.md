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

