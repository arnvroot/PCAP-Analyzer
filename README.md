# PCAP Threat Radar — Offline SOC & DFIR Triage Dashboard

An offline, memory-bounded PCAP/PCAPNG triage engine and dark-themed SOC desktop dashboard built for cybersecurity analysts and DFIR triage. It streams network captures one packet at a time with `dpkt` — the file is never loaded entirely into memory — allowing it to comfortably process multi-gigabyte captures (500MB+ / 500,000+ packets in <45s) under a strict 100MB RAM footprint.

---

## 🌟 Key Features

- **🚀 Multithreaded Desktop GUI (`gui.py`)**: Built with CustomTkinter. Packet parsing runs in a non-blocking background worker thread with thread-safe Queue event streaming.
- **📊 Embedded Data Visualizers**: Dark-styled Matplotlib donut charts for Protocol Distribution (TCP, UDP, IPv4, IPv6, ARP, ICMP) and horizontal bar charts for Top Destination Ports.
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
