# 🛡️ RealAntivirus

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-Educational-lightgrey)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20MacOS-green)
![Status](https://img.shields.io/badge/Status-Active-success)

A **Python-based Antivirus Simulation** that demonstrates the core concepts of Operating Systems, Cybersecurity, and File System Management.  
It detects, quarantines, and deletes potentially harmful files using **signature-based**, **pattern-based**, and **heuristic** detection methods — all within an intuitive **Tkinter GUI** or **command-line interface**.

---

## 📚 Table of Contents

1. [Overview](#-overview)
2. [Features](#-features)
3. [Project Structure](#-project-structure)
4. [Installation](#️-installation)
5. [Usage](#-usage)
6. [Signature Database Format](#-signature-database-format)
7. [How It Works](#-how-it-works)
8. [Example Output](#-example-output)
9. [Educational Value](#-educational-value)
10. [Disclaimer](#⚠️-disclaimer)
11. [Author](#-author)

---

## 🧾 Overview

**RealAntivirus** is an designed to simulate how modern antivirus systems detect and handle malicious files.  
It combines **file hashing**, **pattern analysis**, and **heuristic scanning** to identify suspicious files, with options to **quarantine** or **delete** them securely.

> ⚠️ This is not a commercial antivirus — it’s for educational use only.

---

## ✨ Features

### 🔍 Scanning & Detection
- Recursive file scanning via GUI or CLI  
- Detects using:
  - **Hash-based signature matching**
  - **Text-based pattern matching**
  - **Heuristic analysis** (entropy, suspicious strings, extensions)

### 🧠 Heuristic Analysis
- Calculates **Shannon entropy** for executables (detects packed/encrypted files)
- Flags suspicious content containing:
  - `eval(`, `base64`, `WinExec`, `CreateRemoteThread`, `MZ`, etc.

### 📦 Quarantine & Delete
- Automatically moves infected files to a secure **quarantine folder**
- Manual **restore** or **delete** options from GUI

### 📋 Logging & Reporting
- Detailed logs in `/logs` folder:
  - `scans.log` — scanning results
  - `actions.csv` — all actions with timestamps and hashes

### 👀 Real-Time Monitoring *(Optional)*
- Uses `watchdog` to monitor folders for new or modified files
- Auto-scans and alerts on suspicious activity

### 💻 Tkinter GUI
- User-friendly interface:
  - Folder browsing  
  - Real-time progress updates  
  - File status display (clean/infected)
  - Quarantine/Delete buttons

---

