# PCAP Analyzer : Offline
<img width="1917" height="1041" alt="image" src="https://github.com/user-attachments/assets/d450e806-2f76-4017-a216-9d5c61f2cf5e" />
<img width="1547" height="830" alt="image" src="https://github.com/user-attachments/assets/09a19570-6ddc-498a-a870-48d51079f9c8" />

A lightweight desktop app in Python to analyze PCAP files, detect network threats in real time, and export summary reports as PDFs.
- Reads .pcap files without loading the whole file into RAM.
- Catches cleartext passwords, port scans, and unusual DNS queries in real time.
- Shows live traffic charts and exports an easy-to-read PDF report.
- Can analyze 500MB of pcap file in under 45 seconds
---

## 🌟 Key Features

- **🚀 Multithreaded Desktop GUI (`gui.py`)**: Built with CustomTkinter. Packet parsing runs in a non-blocking background worker thread with thread-safe Queue event streaming.
- **📊 Embedded Data Visualizers**: Dark-styled Matplotlib bar charts for Protocol Distribution (TCP, UDP, IPv4, IPv6, ARP, ICMP) and horizontal bar charts for Top Destination Ports.
- **🚨 Real-Time Security Alerts**: Live threat detection feed with severity badges (`[HIGH]`, `[MED]`, `[LOW]`), live text search filter, and severity filters.
- **🛡️ Multi-Vector Threat Engines**:
  - **Plaintext Credential Leaks**: Detects passwords, API keys, tokens, Basic/Bearer auth in HTTP/FTP/SMTP.
  - **Port Scans**: Detects vertical (one target, many ports) and horizontal scans.
  - **Suspicious DNS / DGA**: Shannon entropy scoring for automated/random domain generation flagging.
  - **C2 Beacon Detection**: Evaluates packet inter-arrival time deltas and coefficient of variation ($CV$).
  - **Network Layer Anomalies**: ARP spoofing / duplicate MAC detection and ICMP ping sweeps.
- **📑 One-Click Executive PDF Threat Reports**: Automated executive triage report generation using ReportLab directly from in-memory analysis data (no intermediate JSON files required).
- **🌐 Web Dashboard Option (`app.py`)**: Companion 14-page Streamlit web dashboard.

---

## 🛠️ Installation

```powershell
# Clone the repository
git clone https://github.com/arnvroot/PCAP-Analyzer.git
cd PCAP-Analyzer

# Install dependencies
pip install -r requirements.txt
```

---

## 🚀 Quickstart

### 1. Modern Desktop GUI (Recommended)
```powershell
python gui.py
```
1. Click **"📁 Select PCAP / PCAPNG"** and choose your capture file.
2. Click **"▶ Run Live Analysis"**.
3. Watch packets, charts, and red flags stream in real time.
4. Click **"📑 Export PDF Threat Report"** to export an executive PDF report.

Note: You can just run " python gui.py " endlessly after installing the requirements once or if the requirements are already installed on your device. 

### 2. Command-Line Interface (CLI)
```powershell
python analyzer.py --pcap C:\captures\incident.pcap --outdir .\output
```

### 3. Streamlit Web Dashboard
```powershell
streamlit run app.py -- --datadir .\output
```

---

## 📦 Project Structure

```
PCAP-Analyzer/
├── gui.py              # Modern CustomTkinter Desktop GUI & Threat Dashboard
├── analyzer.py         # CLI backend streaming triage engine
├── app.py              # Streamlit Web Dashboard entry point
├── pcap_analyzer/      # Core packet parsing and detection algorithms
│   ├── core.py         # Streaming pipeline & flow management
│   ├── detectors.py    # Threat detection rules (scans, beacons, creds)
│   ├── packet_handlers.py
│   ├── protocol_parsers.py
│   └── report_writer.py
├── dashboard/          # Streamlit pages and visualizers
├── requirements.txt    # Project dependencies
└── README.md
```

---

## 🔒 Privacy & Offline Assurance
- 100% offline — zero cloud lookups, zero external API calls.
- Safe for air-gapped forensic environments and sensitive PCAP triage.
