# CoolTR

A modern, dark-themed Windows network diagnostic tool that combines live MTR-style tracerouting, continuous ping monitoring, and deep network info lookups in a single desktop GUI.

![Python](https://img.shields.io/badge/python-3.8%2B-blue) ![Platform](https://img.shields.io/badge/platform-Windows-lightgrey) ![License](https://img.shields.io/badge/license-MIT-green)

## Features

- **Live MTR Traceroute** — Continuously probes each hop along the route, showing real-time per-hop packet loss and latency (last/avg/best/worst/stdev)
- **Continuous Ping Monitor** — Sends one ping per second to the target with running statistics and a timestamped log
- **DNS Lookup** — A, PTR, AAAA, MX, NS, TXT, SOA, and CNAME records
- **GeoIP** — Country, city, ISP, ASN, coordinates, and timezone via ip-api.com
- **ARIN / RDAP** — IP block owner, CIDR range, and contact details from the ARIN registry
- **BGP Info** — Prefix and ASN data via bgpview.io
- **WHOIS** — Domain/IP registration data
- **GitHub Dark theme** — Easy on the eyes for long diagnostic sessions

## Screenshots

> Enter a hostname or IP, hit **Start**, and watch all panels populate in real time.

## Requirements

- Windows 10/11
- Python 3.8+
- No admin rights required

## Installation

```bat
git clone https://github.com/VAROIndustries/CoolTR.git
cd CoolTR
setup.bat
```

`setup.bat` installs the optional Python dependencies:

```
pip install requests dnspython python-whois
```

The app falls back gracefully if any of these are missing — core traceroute and ping work with only Python's standard library.

## Usage

```bat
run.bat
```

Or run directly:

```bash
python cooltr.py
```

1. Type a hostname or IP address into the target field
2. Click **Start**
3. The left panel fills with DNS/GeoIP/ARIN/BGP/WHOIS data
4. The top-right panel shows the live per-hop MTR table
5. The bottom-right panel shows continuous ping stats and a log
6. Click **Stop** to halt probing

## How It Works

| Component | Description |
|-----------|-------------|
| `MTR` | Phase 1 streams `tracert` to discover route hops; Phase 2 spawns a probe thread per hop that continuously pings at the correct TTL to build per-hop statistics |
| `Pinger` | Sends one `ping.exe` call per second, maintaining a 500-sample history |
| `Lookup` | Fires parallel threads for DNS, GeoIP, ARIN RDAP, BGP, and WHOIS lookups |
| `CoolTR` | Tkinter GUI that refreshes the MTR table and ping stats every 500 ms |

No raw sockets are used — all probing is done through the native Windows `ping.exe` and `tracert.exe` binaries, so no elevated privileges are needed.

## Color-Coded Loss Indicator

| Color | Packet Loss |
|-------|-------------|
| Green | 0% |
| Yellow | 1–5% |
| Orange | 6–20% |
| Red | > 20% |

## Dependencies

| Package | Purpose | Required |
|---------|---------|----------|
| `requests` | GeoIP, ARIN, BGP API calls | Optional |
| `dnspython` | Advanced DNS lookups | Optional |
| `python-whois` | WHOIS queries | Optional |

## File Structure

```
CoolTR/
├── cooltr.py        # Main application (single file)
├── requirements.txt # Python dependencies
├── setup.bat        # Dependency installer
└── run.bat          # Application launcher
```
