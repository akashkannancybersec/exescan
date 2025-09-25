# exescan
EXESCAN is an advanced file scanner built in Python to detect malware in executable files. Its main goal is to help security professionals and users identify potentially harmful files before they can compromise a system.

# 🛡️ EXESCAN - Advanced File Scanner

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![Bash](https://img.shields.io/badge/bash-%23121011.svg?style=for-the-badge&logo=gnu-bash&logoColor=white)
![Windows](https://img.shields.io/badge/OS-Windows-%23007ACC.svg?style=for-the-badge)
![Linux](https://img.shields.io/badge/OS-Linux-%23000000.svg?style=for-the-badge&logo=linux&logoColor=white)

---

## 💫 About EXESCAN
EXESCAN is a **Python-based advanced file scanner** designed to detect malware in executable files (`.exe`, `.apk`, `.bat`, `.com`, `.cmd`, `.bin`, `.cpl`).  
It can **scan files on disk** or **inside archives** (`.zip`, `.rar`, `.7z`, `.tar`) with password support and calculates **MD5, SHA1, and SHA256 hashes** for comparison against a database of known malware.

Key features:  
- Typewriter-style console output with ANSI colors  
- Hash calculation for MD5, SHA1, and SHA256  
- Archive scanning with password support  
- Automatic malware detection and quarantine  
- Generates a final tabulated result with status, match percentage, and scan time  

---

## 🛠️ Tech Stack & Tools
**Languages & Libraries:**  
Python | Hashlib | OS | Shutil | Sys | Tabulate | Colorama | zipfile | rarfile | py7zr | tarfile | LZMA  

**Cybersecurity Features:**  
- Malware detection & hash comparison  
- Vulnerability assessment support  
- Executable file handling & archive extraction  

**Supported Security Tools & Techniques:**  
- Nmap, Metasploit, Burp Suite, OWASP ZAP, Nessus, Nikto, Wireshark (for integration/analysis pipelines)  

**Supported OS & Frameworks:**  
- Windows | Linux  
- Compatible with Kali Linux / Parrot OS environments  

---

## ⚡ Features
- **File Scanning:** Detect malware in individual files.  
- **Folder Scanning:** Recursively scan entire directories.  
- **Archive Handling:** Supports `.zip`, `.rar`, `.7z`, `.tar` with password prompts.  
- **Colorful CLI:** Uses `colorama` for visual clarity.  
- **Final Table:** Generates an easy-to-read table with file status, match %, and time taken.  
- **Quarantine:** Moves infected files to `database/infected_files`.  

---

## 🖥️ Usage
1. Clone the repository:
```bash
git clone https://github.com/<your-username>/exescan.git
cd exescan
pip install -r requirements.txt
python exescan.py

