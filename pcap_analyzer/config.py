# all the tunable numbers live here so you don't have to go hunting
# through the detection logic just to change a threshold

import re

TOP_N = 10
UNCOMMON_PORT_THRESHOLD = 5           # a dest port seen fewer than this many times overall is "uncommon"
BEACON_MIN_SAMPLES = 5                # minimum connections in a flow before beacon scoring
BEACON_CV_THRESHOLD = 0.15            # coefficient of variation below this => suspicious regular beaconing
PORT_SCAN_UNIQUE_PORTS_THRESHOLD = 15 # unique dest ports on one target -> flag vertical scan
PORT_SCAN_UNIQUE_HOSTS_THRESHOLD = 15 # unique dest hosts from one src on same port -> flag horizontal scan
DNS_ENTROPY_THRESHOLD = 3.8
DNS_LONG_DOMAIN_THRESHOLD = 45
LARGE_TRANSFER_BYTES = 50 * 1024 * 1024  # 50MB
ICMP_LARGE_PAYLOAD = 1000

CREDENTIAL_PATTERNS = [
    re.compile(rb"Authorization:\s*Basic\s+[A-Za-z0-9+/=]+", re.I),
    re.compile(rb"Authorization:\s*Bearer\s+[A-Za-z0-9\-\._~\+/]+=*", re.I),
    re.compile(rb"password\s*=\s*[^&\s]+", re.I),
    re.compile(rb"passwd\s*=\s*[^&\s]+", re.I),
    re.compile(rb"username\s*=\s*[^&\s]+", re.I),
    re.compile(rb"user\s*=\s*[^&\s]+", re.I),
    re.compile(rb"apikey\s*=\s*[^&\s]+", re.I),
    re.compile(rb"api_key\s*=\s*[^&\s]+", re.I),
    re.compile(rb"secret\s*=\s*[^&\s]+", re.I),
    re.compile(rb"token\s*=\s*[^&\s]+", re.I),
    re.compile(rb"AUTH\s+(LOGIN|PLAIN)", re.I),   # SMTP auth
    re.compile(rb"USER\s+\S+", re.I),              # FTP login
    re.compile(rb"PASS\s+\S+", re.I),              # FTP login
]

DNS_QTYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT", 255: "ANY",
}
