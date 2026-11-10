# Changelog

## v4

- **Reorganized into a proper package structure.** `analyzer.py` and `app.py`
  used to be two giant files (~900 and ~700 lines). They're now thin entry
  points that import from `pcap_analyzer/` (backend) and `dashboard/`
  (frontend), split by responsibility — packet parsing, protocol parsing,
  detection logic, and report writing are all separate files on the backend;
  each dashboard page is its own file on the frontend. Run commands are
  unchanged (`python analyzer.py ...`, `streamlit run app.py -- ...`), only
  the internals moved.
- **Fixed the vertical port scan detector.** It used to count unique
  destination ports per *source only*, ignoring which host was contacted —
  so a normal client browsing a handful of sites could trip it. It's now
  keyed per (source, destination) pair, so it only fires when one host
  actually probes many ports on the *same* target, and the alert message
  now names the target instead of just the source.
- **PDF report improvements:**
  - Added color-coded severity (red/orange/green) to alerts.
  - Removed decorative table styling (dark header fills, gray row striping)
    in favor of plain grid tables — only the severity text itself is
    colored, nothing else.
  - Alerts and Credential Leak Detail now appear first, right after the
    report header, instead of after the summary/protocol stats.
  - Removed a forced page break so everything flows continuously with
    normal spacing instead of jumping to a new page.
- **Added CSV export** — a flat, readable file with a report header block,
  a severity count summary, and clearly labeled ALERTS / CREDENTIAL LEAKS
  sections.
- **Colored callouts across dashboard pages** (DNS, HTTP, TLS, Port
  Analysis, Port Scan Detection, Conversations) — blue/orange/red/green
  boxes reflecting what was actually found, instead of plain gray captions
  everywhere.
- **Renamed and rebranded** — "PCAP SOC Dashboard" (🛡️) is now
  "Pcap Trace : Packet File Inspector" (📦), in both the browser tab and
  the sidebar header.
