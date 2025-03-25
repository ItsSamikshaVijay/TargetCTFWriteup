# Cybersecurity Writeups

## Overview

This repository contains my solutions for various cybersecurity challenges, including defensive and offensive security tasks. The challenges involve vulnerability identification, decoding encrypted data, Suricata analysis, and phishing simulations. The solutions are broken into two sections: Defensive Security and Offensive Security. 

---

## Table of Contents

1. [Defensive Security Writeups](#defensive-security-writeups)
   - [Problem 1: Network Vulnerabilities](#problem-1-network-vulnerabilities)
   - [Problem 2: QR Code Decryption](#problem-2-qr-code-decryption)
   - [Suricata Analysis](#suricata-analysis)
2. [Offensive Security Writeups](#offensive-security-writeups)
   - [Information Gathering](#information-gathering)
   - [Website Phishing Simulation](#website-phishing-simulation)
   - [XOR Encryption with Base64](#xor-encryption-with-base64)

---

## Defensive Security Writeups

### Problem 1: Network Vulnerabilities

In this challenge, I was provided with a network diagram and a JSON file containing security vulnerabilities detected through Centauros. 

Steps:
1. Analyzed the network diagram to identify the hosts within the environment.
2. Cross-referenced each host with the detected vulnerabilities from Centauros.
3. Prioritized my assessment based on severity levels provided in the JSON file.

The five critical vulnerabilities I focused on are:

- **Google Chrome < 125.0.6422.112 Vulnerability**
- **Microsoft Edge (Chromium) < 126.0.2592.56 Multiple Vulnerabilities**
- **Windows 10 Version 21H2 Security Update**
- **Python Unsupported Version Detection**

After analyzing each of the vulnerabilities, I chose **Windows 10 Version 21H2 Security Update (CVE-2024-29994)** as the most critical, given its potential OS-level impact.

### Problem 2: QR Code Decryption

In this challenge, I scanned a QR code and received the output `Synt{rirel_pgs_arrqf_ebg13}`. This seemed to be an encoded message. After analyzing the format, I realized that the message was encoded using the **ROT13** cipher. 

- **Decoded message**: `Flag{evershouldbe13}`
- The flag was: `flag{ever_should_be_13}`.

### Suricata Analysis

I analyzed Suricata logs to detect malicious activity:

1. **Identified compromised users** by tracking the source IP addresses.
2. **Multiple POST requests** pointed to the same destination IP, indicating credential exfiltration.

Through this, I discovered 8 distinct compromised users by analyzing the Suricata logs.

---

## Offensive Security Writeups

### Information Gathering

In this task, I was asked to gather information about a potential target employee, Alex Lee, who had no publicly available information. Through social media connections and researching friends of Alex, I discovered a GitHub link that led me to the flag.

**Steps**:
1. Searched for friends of Alex Lee (Olivia Stone, Maxwell, Camilla Grey).
2. Found a reply to Camilla's post from Alex Lee with a link to their GitHub.
3. Accessed the GitHub to retrieve the flag.

### Website Phishing Simulation

For the phishing simulation, I cloned a website and used a local server to host it. I set default credentials (username: username, password: password), which allowed me to retrieve the flag.

**Steps**:
1. Installed a website cloning tool (Cyotek WebCopy).
2. Hosted the cloned website locally using Microsoft's `HTTP Server - Host static webpages`.
3. Used default credentials to access the site and retrieve the flag.

The flag was: `h4rv3ster_h3r0`.

### XOR Encryption with Base64

In this challenge, the flag was encoded using Base64 and XOR encryption. The key for XOR decryption was hidden in the date of a company email. 

**Steps**:
1. Decrypted the Base64 encoded message using XOR with the company's email date.
2. Reversed the XOR encryption to retrieve the correct flag.

Finally, I submitted the QR code after encoding it back into Base64 to obtain the correct flag.

---

## Conclusion

This repository showcases my approach to solving different cybersecurity challenges. Each task required critical thinking, an understanding of various tools, and the ability to apply theory to real-world scenarios. I look forward to expanding my knowledge and continuing to tackle more challenges in the future.

---

### License

This repository is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
