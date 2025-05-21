# ioc_collector
A Python-based threat intel collector that pulls IOCs from hundreds of threat feeds and normalizes them for downstream consumption.

# Key Features

- Collects IOCs from plaintext, CSV, and JSON sources
- Deduplicates IOCs (IP, domain, hash, URL)
- Normalizes feeds into structured JSON format
- Supports feeds from Abuse.ch, Blocklist.de, IPSum, CISA, OpenPhish, and more
- Extensible with new feed types
- Designed for integration with SIEMs, EDRs, and other security tools

# IOC Types Supported

- IP addresses
- Domain names
- Hashes: MD5, SHA1, SHA256
- URLs

# Usage

```bash
python3 ioc_collector.py
