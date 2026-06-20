# Cyber Forensics Lightweight SIEM Tool

A resource-efficient, lightweight Security Information and Event Management (SIEM) solution designed to assist security analysts, students, researchers, and organizations in collecting, analyzing, and investigating security-related events from log data. 

The platform centralizes log analysis, normalizes event data, detects suspicious activities using predefined rules, and enables deeper incident investigation through an intuitive, web-based dashboard. By incorporating digital forensics concepts, this tool bridges the gap between proactive monitoring and post-incident evidence analysis without the complexity or resource overhead of enterprise-grade software.

---

## 📌 Executive Summary & Educational Value

This project is engineered to serve as both a practical cybersecurity monitoring utility and an educational learning platform. It provides real-world exposure to Security Operations Center (SOC) environments by demonstrating the practical implementation of:
* **Security Information and Event Management (SIEM)** core mechanics.
* **Digital Forensics** event reconstruction and evidence parsing.
* **Log Analysis & Normalization** across disparate schemas.
* **Threat Detection & Analytics** using rule-based engines.
* **Incident Investigation Workflows** & Alert Management.

---

## 🚀 Key Features & Subsystems

### 1. Log File Ingestion
The SIEM allows analysts to centralize log data by uploading and parsing files from multiple distinct sources. Supported log families include:
* **OS Telemetry:** Windows Event Logs, Linux System Logs, and Authentication Logs.
* **Network Elements:** Firewall Logs and Web Server Logs.
* **Application Activity:** General Application Logs, Security Logs, and Custom Text-Based Logs.

### 2. Stream Parsing & Log Normalization
To resolve format differences across systems, the parsing engine strips raw logs into standardized JSON structures. This provides consistent event representation, cleaner data correlation, and rapid querying.
* **Raw Input Example:** `{"EventID": 4625, "User": "Administrator", "Source": "Windows"}`
* **Normalized Output Example:** `{"event_type": "Failed Login", "user": "Administrator", "source": "Windows"}`

### 3. Rule-Based Threat Detection Engine
The custom analytical engine continuously scans normalized events against predefined security signatures to automate threat identification. 
* **Brute Force Login Detection:** Triggers if failed logins exceed 5 within the configured investigation window.
* **Unauthorized Access Detection:** Triggers if a login originates from an unexpected or suspicious source.
* **Privilege Escalation Detection:** Triggers if administrative privileges are assigned unexpectedly to an account.

### 4. Granular Alert Triage & Severity Matrix
When a correlation signature matches, the system instantiates structured alerts categorized into a distinct prioritization matrix:

| Severity Level | Description | Action Required |
| :--- | :--- | :--- |
| **Low** | Informational events. | Logged for routine compliance review. |
| **Medium** | Suspicious activity requiring review. | Requires active analytical investigation. |
| **High** | Potential security compromise. | Escalated for immediate incident response. |

Each alert object explicitly encapsulates an Alert ID, Timestamp, Severity Level, Event Source, Detection Rule, Alert Description, and Associated Event Metadata.

### 5. Incident Investigation & Forensics Support
Moving beyond standard logging, the **Incident Investigation Module** allows analysts to reconstruct the exact attack progression:
* **Forensic Timeline Analysis:** Automatically chains historical events to track user activities sequentially.
* **Evidence Preservation:** Relies on strict local state engines to keep log pointers intact, preventing tampering or data gaps.
* **Targeted Parameter Filtering:** Enables immediate querying across variables like Username, Event Type, IP Address, Timestamp, Severity, Log Source, and targeted Keywords.

---

## 💻 Built-In Security Controls & Log Integrity

The platform implements programmatic defensive engineering principles to secure itself from malicious tampering and preserve evidence chain-of-custody:
* **Log Integrity Protection (SHA-256):** To maintain forensic validity, the platform calculates cryptographic SHA-256 hashes for all ingested files upon import. These checksums are routinely verified against active files to detect unauthorized changes, modifications, or log-wiping attempts by adversaries attempting to cover their tracks.
* **Role-Based Access Control (RBAC) & Authentication:** Protects dashboard visibility and management modules.
* **Input Validation:** Strict parsing bounds on log file uploads to prevent injection vulnerabilities.
* **Audit Support:** Tracks alert state modifications and investigator updates for internal audit compliance.

---

## 🛠️ System Architecture & Data Workflow

The platform maps incoming files across a synchronized processing loop:
```text
[Log File Upload] ──> [Log Parsing] ──> [Event Normalization] ──> [Database Storage (siem.db)]
                                                                          │
[Dashboard UI] <── [Alert Generation] <── [Custom Detection Engine] <─────┘
```

**System Architecture**
```text
Python-Custom-SIEM-Platform/
├── .gitignore
├── collector/
│   └── log_collector.py
├── config/
│   └── log_sources.json
├── dashboard/
│   ├── app.py
│   ├── static/
│   │   └── styles.css
│   └── templates/
│       ├── alerts.html
│       ├── base.html
│       ├── incidents.html
│       ├── index.html
│       ├── logs.html
│       └── timeline.html
├── database/
│   └── db_manager.py
├── detection/
│   ├── _init_.py
│   ├── alert_manager.py
│   ├── engine.py
│   ├── incident_manager.py
│   ├── rule_engine.py
│   ├── rules/
│   │   ├── _init_.py
│   │   ├── base_rule.py
│   │   ├── brute_force.py
│   │   ├── firewall_abuse.py
│   │   └── system_anomaly.py
│   ├── state_manager.py
│   └── timeline_manager.py
├── logs/
│   └── sample_logs.log
├── main .py
├── parsers/
│   └── log_parser.py
├── siem.db
└── state/
    ├── detection_state.json
    ├── file_offsets.json
    └── state_manager.py
```

---

## ⚙️ Core Technology Stack

*   **Backend & Security Analytics:** Python , Flask
    
*   **Database Management System:** SQLite
    
*   **Frontend Interface UI:** HTML , CSS , JavaScript
    
*   **Data Visualization Elements:** Chart.js
    
---

## 🔮 Future Enhancements

The following roadmap features are planned for future releases to transition this platform toward enterprise preparedness:

* **Live Log Ingestion & Real-Time Event Processing:** Sub-second data analysis stream integration.  
* **Multi-System Log Collection:** Distribution agents to collect data from decentralized remote endpoints.  
* **Advanced Correlation Rules & MITRE ATT&CK Mapping:** Explicit categorization of signatures against world-wide threat behavior maps.  
* **Machine Learning-Based Anomaly Detection:** Moving beyond static signatures into baseline behavioral heuristics.  
* **SOAR Integration:** Automated playbook execution paths to trigger network isolating blocks upon malicious activity discovery.  
* **Automated Report Generation & Alerting:** Automated PDF security health outputs and direct email routing pipelines.

---

## 📸 Interface & Dashboards

*Below are visual previews of the Cyber Forensics Lightweight SIEM Tool in action.*

### 1. Primary SOC Dashboard View
The centralized analytical hub featuring live event metrics, severity distribution metrics using Chart.js, and active threat trends.
<img width="1901" height="891" alt="image" src="https://github.com/user-attachments/assets/60fef55d-495b-4ad7-abf2-90cee31c48a4" />

### 2. Normalized Grid Interface
Demonstrating how raw, multi-source log formats (Windows Event IDs, Linux Syslog, Web logs) are parsed into a uniform, searchable data schema.
<img width="1768" height="892" alt="image" src="https://github.com/user-attachments/assets/9a01137e-c04d-4f44-b656-8875209c59ee" />

### 3. Active Alert Triage Panel
Real-time rule engine matches displaying prioritized, color-coded threat alerts (Low, Medium, High) for rapid analyst assessment.
<img width="1891" height="866" alt="image" src="https://github.com/user-attachments/assets/4e01b35f-248c-42df-8c45-d7f04a9ae7fe" />

### 4. Forensics Timeline Reconstruction
The incident investigation layout tracking correlated security anomalies chronologically to reconstruct an adversary's execution steps.
<img width="1897" height="757" alt="image" src="https://github.com/user-attachments/assets/abf19177-f1ac-428d-99b2-f428f722ccdd" />
<img width="1913" height="810" alt="image" src="https://github.com/user-attachments/assets/073f9cb4-54a0-4211-95c1-bdef0e976e64" />


---

## 🚀 Installation Guide & Environment Setup

### Prerequisites
Ensure you have **Python 3.10+** installed on your system.

### 1. Repository Setup
Clone the codebase directly to your workspace via your terminal:
```bash
git clone [https://github.com/Anmol2426/Python-Custom-SIEM-Platform.git](https://github.com/Anmol2426/Python-Custom-SIEM-Platform.git)
cd Python-Custom-SIEM-Platform
```
### 2. Environment Segmentation
Create and initialize an isolated Python virtual environment to manage dependencies cleanly:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows environments: .\venv\Scripts\activate
```
### 3. Dependency Aggregation
Install all required third-party backend packages and engine requirements exactly as specified:
```bash
pip install -r requirements.txt
```
### 4. Running the Ecosystem
The entire platform is synchronized and executed from a single initialization script. When executed, the application boots the log ingestion engine, spins up the threat detection loop, triggers SHA-256 integrity verifications, and automatically launches the Flask-based web interface in your default browser.
To start the SIEM platform, simply execute the main file:
```bash
python main.py
```
If your web browser does not automatically pull up the analyst interface, manually open your browser and navigate to: ```http://127.0.0.1:5000 ```


