
                                    ╔═══════════════════════════════════════════════════════════════════╗                                       
                                    ║                                                                   ║                                              
                                    ║    ██████╗   ███████╗  ██████╗  █████╗   ██╗     ██╗              ║                                          
                                    ║    ██╔══██╗  ██╔════╝ ██╔════╝  ██╔══██╗ ██║     ██║              ║                                           
                                    ║    ██████╔╝  █████╗   ██║       ███████║ ██║     ██║              ║                                          
                                    ║    ██╔══██╗  ██╔══╝   ██║       ██╔══██║ ██║     ██║              ║                                           
                                    ║    ██║  ██║  ███████╗╚██████╗   ██║  ██║ ███████╗███████╗         ║                                             
                                    ║    ╚═╝  ╚═╝  ╚══════╝ ╚═════╝   ╚═╝  ╚═╝ ╚══════╝╚══════╝         ║                                         
                                    ║                                                                   ║                                        
                                    ║ ████████╗██╗███╗   ███╗███████╗██╗     ██╗ ███╗   ██╗███████╗     ║                                          
                                    ║ ╚══██╔══╝██║████╗ ████║██╔════╝██║     ██║ ████╗  ██║██╔════╝     ║                                          
                                    ║    ██║   ██║██╔████╔██║█████╗  ██║     ██║ ██╔██╗ ██║█████╗       ║                                                
                                    ║    ██║   ██║██║╚██╔╝██║██╔══╝  ██║     ██║ ██║╚██╗██║██╔══╝       ║                                                
                                    ║    ██║   ██║██║ ╚═╝ ██║███████╗███████╗██║ ██║ ╚████║███████╗     ║                                                
                                    ║    ╚═╝   ╚═╝╚═╝     ╚═╝╚══════╝╚══════╝╚═╝ ╚═╝  ╚═══╝╚══════╝     ║                                                  
                                    ║                                                              v1.0 ║                                             
                                    ╚═══════════════════════════════════════════════════════════════════╝      

  
# 🔍 RecallTimeline

### Open-Source Forensic Timeline Reconstruction Tool for Windows Recall EXIF Artifacts

[![Python Version](https://img.shields.io/badge/python-3.9+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)](https://github.com/Muhammad-Shoaib-Ishaq-Khan/RecallTimeline)
[![DFIR](https://img.shields.io/badge/DFIR-Tool-red)](https://github.com/Muhammad-Shoaib-Ishaq-Khan/RecallTimeline)
[![GitHub Stars](https://img.shields.io/github/stars/Muhammad-Shoaib-Ishaq-Khan/RecallTimeline?style=social)](https://github.com/Muhammad-Shoaib-Ishaq-Khan/RecallTimeline)

**First open-source DFIR tool for Windows Recall forensics**

*Automated extraction · Timeline reconstruction · Anomaly detection · Forensic reporting*

```python                                                                                                                              
┌───────────────────────────────────────────────────────────────────────────┐                                                                     
│                                                                           │                                                             
│         🗂️ ukg.db + 🖼️ JPEG/EXIF + 📁 Flat Captures + ✅ Autopsy        │                                                                    
│                                                                           │                                                                     
│                                    ▼                                      │                                                                    
│                        ╔═══════════════════════╗                          │                                                     
│                        ║ Four-Strategy         ║                          │                                                           
│                        ║ MakerNote Decoder     ║                          │                                                             
│                        ╚═══════════════════════╝                          │                                                 
│                                    ▼                                      │                                                          
│                        ╔═══════════════════════╗                          │                                                                   
│                        ║ 29 Keyword Rules      ║                          │                                                            
│                        ║ 7 Threat Categories   ║                          │                                                                     
│                        ║ Burst Detection       ║                          │                                                                
│                        ╚═══════════════════════╝                          │                                                          
│                                    ▼                                      │                                                        
│              ┌──────────────┬───────────────┬──────────────┐              │                                                           
│              │       📄 CSV │ 🌐 HTML      │ 📑 PDF       │              │                                                                     
│              │      Machine │ Interactive   │ Forensic     │              │                                                           
│              │     Readable │ Dashboard     │ Ready        │              │                                                              
│              └──────────────┴───────────────┴──────────────┘              │                                                                      
│                                                                           │                                                                       
└───────────────────────────────────────────────────────────────────────────┘                                                                        
  ```                                                                                                                                      

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [What is Windows Recall?](#-what-is-windows-recall)
- [Forensic Artifacts](#-forensic-artifacts)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage Guide](#-usage-guide)
- [Case Study: Case_E001](#-case-study-case_e001)
- [Output Reports](#-output-reports)
- [Anomaly Detection Rules](#-anomaly-detection-rules)
- [Performance](#-performance)
- [Limitations](#-limitations)
- [Contributing](#-contributing)
- [License](#-license)
- [Citation](#-citation)
- [Authors](#-authors)
- [Acknowledgments](#-acknowledgments)

---

## 📖 Overview

**RecallTimeline** is a Python-based command-line forensic tool that automates the extraction, timeline reconstruction, and anomaly detection of **Windows Recall** artifacts. It processes EXIF MakerNote metadata (tag `0x927C`) from JPEG screenshots and the `ukg.db` SQLite database to generate comprehensive forensic timelines.

```python
# Quick Example
from RecallTimeline import RecallTimeline

recall = RecallTimeline()
recall.extract_artifacts("./sample-dataset")
recall.detect_anomalies()
recall.generate_reports()

🎯 First of its kind — No open-source tool existed before this research to automatically capture, timeline, anomaly score, or report on Windows Recall artifacts.
✨ Features
Feature	Description
🗂️ Multi-Source Artifact Extraction	Processes ukg.db, ImageStore JPEGs, and flat-folder captures
🔓 Four-Strategy MakerNote Decoder	Decodes Binary Key-Value, Length-Prefixed JSON, Raw UTF-8 JSON, and UTF-16 LE JSON
🚨 Intelligent Anomaly Detection	29 keyword-based rules across 7 threat categories + burst detection
📊 Comprehensive Reports	CSV, Interactive HTML, and Forensic PDF outputs
✅ Evidence Corroboration	Autopsy CSV integration for two-source verification
🔐 Chain of Custody	SHA-256 hashes and examiner signatures in PDF reports
⚡ Blazing Fast	Processes 65 events in <5 seconds (180x faster than manual analysis)
🖥️ What is Windows Recall?
```
Windows Recall is an AI-powered feature on Copilot+ PCs that captures JPEG screenshots of user activity every few seconds.

```python
┌─────────────────────────────────────────────────────────────────┐
│                    Windows Recall Artifacts                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   📸 JPEG Screenshot                    🗄️ ukg.db Database     │
│   ┌─────────────────────┐              ┌─────────────────────┐  │
│   │ EXIF Tag 0x927C     │              │ WindowCapture       │  │
│   │ • Timestamp (UTC)   │              │ Web                 │  │
│   │ • WindowTitle       │              │ WindowCaptureText   │  │
│   │ • ProcessPath       │              │ Index (OCR)         │  │
│   │ • URL               │              └─────────────────────┘  │
│   │ • SnapshotId        │                                       │
│   └─────────────────────┘                                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```
🗂️ Forensic Artifacts
```python
%AppData%\Local\CoreAIPlatform.00\UKP\{GUID}\
│
├── 📁 ImageStore/
│   ├── 🖼️ 01aae15b-46b2-5b9e-8bbe-c431d0a6cd4c
│   ├── 🖼️ 064bbda5-9e1e-ba12-0d8d-a29c0d5befa6
│   └── ... (JPEG files with EXIF MakerNote at tag 0x927C)
│
└── 🗄️ ukg.db (SQLite database)
    ├── 📊 WindowCapture table
    ├── 🌐 Web table
    └── 📝 WindowCaptureTextIndex table (OCR content)
```
🏗️ Architecture
```python
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                              RecallTimeline Pipeline                                │
├─────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                     │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐            │
│   │   ukg.db     │  │   JPEGs      │  │ Flat Folder  │  │  Autopsy     │            │
│   │  (SQLite)    │  │  (EXIF)      │  │  Captures    │  │    CSV       │            │
│   └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘            │
│          │                 │                 │                 │                    │
│          └─────────────────┼─────────────────┼─────────────────┘                    │
│                            ▼                 ▼                                      │
│                   ┌─────────────────────────────────┐                               │
│                   │         PARSER MODULE           │                               │
│                   │  ┌─────────────────────────┐    │                               │
│                   │  │ _decode_makernote()     │    │                               │
│                   │  │ • Strategy 1: Binary KV │    │                               │
│                   │  │ • Strategy 2: Len-JSON  │    │                               │
│                   │  │ • Strategy 3: Raw UTF-8 │    │                               │
│                   │  │ • Strategy 4: UTF-16 LE │    │                               │
│                   │  └─────────────────────────┘    │                               │
│                   │  parse_ukg_db() ─── JOIN query  │                               │
│                   │  parse_jpeg() ─── PIL EXIF      │                               │
│                   └─────────────────┬───────────────┘                               │
│                                     ▼                                               │
│                   ┌─────────────────────────────────┐                               │
│                   │       TIMELINE BUILDER          │                               │
│                   │  • merge_all_sources()          │                               │
│                   │  • dedup by SnapshotId          │                               │
│                   │  • UTC timestamp sort           │                               │
│                   │  • _merge_autopsy()             │                               │
│                   └─────────────────┬───────────────┘                               │
│                                     ▼                                               │
│                   ┌─────────────────────────────────┐                               │
│                   │       ANOMALY DETECTOR          │                               │
│                   │  ┌─────────────────────────┐    │                               │
│                   │  │ PASS 1: 29 Keyword Rules│    │                               │
│                   │  │ • Confidential Files    │    │                               │
│                   │  │ • Cloud Storage         │    │                               │
│                   │  │ • LOLBins               │    │                               │
│                   │  │ • Credentials           │    │                               │
│                   │  └─────────────────────────┘    │                               │
│                   │  PASS 2: Burst Detection        │                               │
│                   │  • <5 second threshold          │                               │
│                   └─────────────────┬───────────────┘                               │
│                                     ▼                                               │
│                   ┌─────────────────────────────────┐                               │
│                   │         EXPORT MODULE           │                               │
│                   │  ┌─────────┐ ┌─────────┐ ┌─────┐│                               │
│                   │  │  CSV    │ │  HTML   │ │ PDF ││                               │
│                   │  │ Machine │ │ Chart.js│ │Chain││                               │
│                   │  │Readable │ │Dashboard│ │Cust.││                               │
│                   │  └─────────┘ └─────────┘ └─────┘│                               │
│                   └─────────────────────────────────┘                               │
│                                                                                     │
└─────────────────────────────────────────────────────────────────────────────────────┘
```
📦 Installation
Prerequisites

    Python 3.9+
  pip (Python package manager)

Step 1: Clone the Repository

git clone https://github.com/Muhammad-Shoaib-Ishaq-Khan/RecallTimeline.git
cd RecallTimeline

Step 2: Install Dependencies

pip install -r requirements.txt

requirements.txt:

Pillow>=10.0.0    # EXIF processing
fpdf2>=2.7.0      # PDF generation
openpyxl>=3.1.0   # XLSX export (optional)

Step 3: Verify Installation
bash

python RecallTimeline.py --help

🚀 Quick Start
Basic Usage
python RecallTimeline.py analyse --recall-dir ./sample-dataset --case CASE_NAME

Full Usage with Autopsy Corroboration
python RecallTimeline.py analyse \
    --recall-dir ./sample-dataset \
    --case Case_E001 \
    --autopsy-csv ./autopsy_export.csv \
    --output ./results

📖 Usage Guide
Command Line Arguments
Argument	Required	Description
--recall-dir	✅	Path to Recall artifacts (ukg.db + ImageStore)
--case	✅	Case name for output files
--autopsy-csv	❌	Autopsy CSV for evidence corroboration
--output	❌	Output directory (default: ./recall_output)
--no-pdf	❌	Disable PDF generation
--no-html	❌	Disable HTML generation
Example Commands
1. Basic Analysis
python RecallTimeline.py analyse --recall-dir ./sample-dataset --case Investigation_001

2. Full Analysis with All Outputs
python RecallTimeline.py analyse \
    --recall-dir ./sample-dataset \
    --case Case_E001 \
    --autopsy-csv ./evidence/autopsy.csv \
    --output ./forensic_report

3. Quick Analysis (No PDF)
python RecallTimeline.py analyse --recall-dir ./sample-dataset --case QuickScan --no-pdf

📊 Case Study: Case_E001
Scenario

Corporate insider threat case involving data exfiltration via cloud storage.
Results
```python
┌─────────────────────────────────────────────────────────────────┐
│                    Case_E001 Analysis Metrics                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Total Events Parsed      ████████████████████ 65              │
│   Flagged Events           ██████████░░░░░░░░░░ 34 (52.3%)      │
│   Clean Events             █████████░░░░░░░░░░░ 31 (47.7%)      │
│   Autopsy Corroborated     ████████░░░░░░░░░░░░ 25 (38.5%)      │
│   Unique Processes         █████████████████░░░ 26              │
│   Unique URLs Recorded     ███████████░░░░░░░░░ 17              │
│   Investigation Period     ████████████████████ 37 days         │
│   Processing Time          ⚡ < 5 seconds                       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```
Detected Anomalies
Time	Activity	Anomaly Type
09:11:43	Excel - CONFIDENTIAL_Q1.xlsx	📁 Confidential File
09:11:49	MEGAsync - Upload	☁️ Cloud Upload
09:11:58	secret_strategy.docx	📁 Confidential File
13:48:40-48	mega.nz (3x in 8 sec)	⚡ Burst Activity
13:50:10	PowerShell	💻 LOLBin Execution

📄 Output Reports
1. CSV Report (Machine-Readable)

15-column tabular format compatible with SIEM and Timesketch:
Timestamp,WindowTitle,ProcessPath,URL,Flags,OCRText,...
2026-03-15T09:11:43Z,Excel - CONFIDENTIAL_Q1.xlsx,C:\Program Files\...\EXCEL.EXE,,confidential,...

2. HTML Report (Interactive Dashboard)

    📊 Chart.js bar chart (events per hour)
    🥧 Doughnut chart (events per process)
    🔍 Searchable/sortable event table
    📋 Sidebar event detail panel

3. PDF Report (Forensic-Ready)

    📑 Colored summary cards
    🚩 Full flagged events table
    ✅ Autopsy corroboration section
    🔐 SHA-256 integrity verification
    📝 Chain-of-custody block with signatures

🔧 Anomaly Detection Rules
7 Thematic Categories (29 Keyword Rules)
```python
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          ANOMALY DETECTION ENGINE                               │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   ┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐     │
│   │  📁 Confidential   │  │  ☁️ Cloud Storage   │  │  📦 Data Staging    │     │
│   │  Files              │  │                     │  │                     │     │
│   │  • confidential     │  │  • mega.nz          │  │  • 7-zip            │     │
│   │  • secret           │  │  • dropbox          │  │  • winrar           │     │
│   │  • private          │  │  • google drive     │  │  • pastebin         │     │
│   │  • restricted       │  │  • onedrive         │  │  • pasteboard       │     │
│   │  • classified       │  │  • box.com          │  │                     │     │
│   └─────────────────────┘  └─────────────────────┘  └─────────────────────┘     │
│                                                                                 │
│   ┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐     │
│   │  💻 LOLBins         │  │  🔌 Remote Access  │  │  🔑 Credentials    │     │
│   │  • powershell       │  │  • putty            │  │  • password         │     │
│   │  • cmd.exe          │  │  • mstsc            │  │  • api key          │     │
│   │  • wscript          │  │  • vnc              │  │  • token            │     │
│   │  • cscript          │  │  • anydesk          │  │  • secret           │     │
│   │  • mshta            │  │  • teamviewer       │  │  • rsa              │     │
│   │  • regsvr32         │  │                     │  │                     │     │
│   └─────────────────────┘  └─────────────────────┘  └─────────────────────┘     │
│                                                                                 │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │                         ☁️ Cloud Development                            │   │
│   │  • aws console  • azure portal  • github  • gcloud                      │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
│                                                                                 │
│   ⚡ Burst Detection: Consecutive events <5 seconds apart → "burst_activity"    │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```
⚡ Performance
Dataset Size	Processing Time	Memory Usage	Output Size (HTML)
65 events (Case_E001)	< 5 sec	< 50 MB	~180 KB
100 events (synthetic)	~7 sec	< 60 MB	~270 KB
500 events (synthetic)	~19 sec	< 85 MB	~1.3 MB
1,000 events (synthetic)	~38 sec	< 100 MB	~2.6 MB

```python
┌─────────────────────────────────────────────────────────────────────────────────┐
│                     Performance: RecallTimeline vs Manual                       │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│   Manual Analysis (ExifTool + SQLite + Excel)                                   │
│   ████████████████████████████████████████████████████████████████ 168 min      │
│                                                                                 │
│   RecallTimeline                                                                │
│   ██ < 5 sec                                                                    │
│                                                                                 │
│   ⚡ ~180x FASTER                                                               │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

🛡️ Limitations
Limitation	Mitigation
Requires Windows Recall to be enabled	Opt-in feature on Copilot+ PCs
Latin-1 font encoding in PDF	Unicode font planned for v2.0
Relies on default Microsoft schema	Parser adaptation for future Recall versions
No Windows Event Log integration	Planned for v2.0
🤝 Contributing

We welcome contributions from the DFIR community!
How to Contribute

    Fork the repository
    Create a feature branch:

    git checkout -b feature/amazing-feature
    Commit your changes:

    git commit -m "Add amazing feature"

    Push to the branch:
    git push origin feature/amazing-feature
    Open a Pull Request

Contribution Areas

    🐛 Bug fixes
    ✨ New anomaly detection rules
    📚 Documentation improvements
    🧪 Additional test cases
    🔌 Integration with other DFIR tools
    📜 License

This project is licensed under the MIT License — see the LICENSE file for details.

MIT License
Copyright (c) 2026 Muhammad Shoaib Ishaq Khan, Ahmad Hassan, Zoha Nazar
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files...

📚 Citation
If you use RecallTimeline in your research, please cite:

bibtex
```python
@misc{khan2026recalltimeline,
  author = {Muhammad Shoaib Ishaq Khan and Ahmad Hassan and Zoha Nazar and Ali Sufyan},
  title = {RecallTimeline: An Open-Source Forensic Timeline Reconstruction 
           Tool for Windows Recall EXIF Artifacts},
  year = {2026},
  publisher = {GitHub},
  url = {https://github.com/Muhammad-Shoaib-Ishaq-Khan/RecallTimeline}
}
```
👥 Authors
    Author	Role	Contact
    Muhammad Shoaib Ishaq Khan	Lead Developer & Primary Author	GitHub
    Ahmad Hassan	ukg.db Parser & Anomaly Engine	-
    Zoha Nazar	Report Generation & Autopsy Integration	-
    Dr. Ali Sufiyan	Supervisor	-

📞 Support & Contact
    Issues: GitHub Issues
    Discussions: GitHub Discussions
    
```python
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║ 🔍 RecallTimeline — First Open-Source DFIR Tool for Windows Recall Forensics  ║
║                                                                               ║
║   MIT Licensed · Free for Academic and Professional Use                       ║
║                                                                               ║
║   ⭐ If this tool helped you, please star the repository! ⭐                 ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```
