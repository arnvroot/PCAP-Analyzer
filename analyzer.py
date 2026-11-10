"""
analyzer.py
===========
Offline, memory-bounded PCAP/PCAPNG analyzer for DFIR / SOC triage.

This is just the CLI entry point now -- the actual logic lives in the
pcap_analyzer/ package (packet_handlers, protocol_parsers, detectors,
report_writer, all glued together in core.py). Split up so it's easier
to find the piece you're looking for instead of scrolling one huge file.

Usage
-----
    python analyzer.py --pcap capture.pcap --outdir ./output

Only the Python standard library + dpkt are required at runtime.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

try:
    import dpkt  # noqa: F401  (just checking it's installed before we get further)
except ImportError:
    print("ERROR: dpkt is required. Install offline with: pip install dpkt", file=sys.stderr)
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("pcap_analyzer")

# turns on ansi colors on windows terminals, no-op on linux/mac
if sys.platform == "win32":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

from pcap_analyzer import PcapAnalyzer


def main() -> None:
    parser = argparse.ArgumentParser(description="Offline streaming PCAP/PCAPNG analyzer for DFIR/SOC triage.")
    parser.add_argument("--pcap", required=True, help="Path to .pcap or .pcapng file")
    parser.add_argument("--outdir", default="./output", help="Directory to write JSON outputs")
    args = parser.parse_args()

    if not Path(args.pcap).exists():
        log.error(f"File not found: {args.pcap}")
        sys.exit(1)

    analyzer = PcapAnalyzer(args.pcap, args.outdir)
    try:
        analyzer.run()
    except KeyboardInterrupt:
        log.warning("Interrupted by user, results written up to point of interruption.")


if __name__ == "__main__":
    main()
