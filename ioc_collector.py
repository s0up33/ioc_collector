
import ipaddress
import requests
from io import StringIO
import csv
import json
from datetime import datetime, timezone
from tqdm import tqdm

feed_definitions = {
  "plaintext": [
    "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
    "https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.txt",
    "https://threatfox.abuse.ch/downloads/hostfile/",
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "https://feodotracker.abuse.ch/blocklist/",
    "https://bazaar.abuse.ch/export/txt/md5/recent/",
    "https://bazaar.abuse.ch/export/txt/sha1/recent/",
    "https://bazaar.abuse.ch/export/txt/sha256/recent/",
    "https://lists.blocklist.de/lists/all.txt",
    "https://lists.blocklist.de/lists/ssh.txt",
    "https://lists.blocklist.de/lists/mail.txt",
    "https://lists.blocklist.de/lists/apache.txt",
    "https://lists.blocklist.de/lists/imap.txt",
    "https://lists.blocklist.de/lists/bots.txt",
    "https://lists.blocklist.de/lists/bruteforcelogin.txt",
    "https://lists.blocklist.de/lists/strongips.txt",
    "https://lists.blocklist.de/lists/ftp.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/2.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/4.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/5.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/6.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/7.txt",
    "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/8.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/all.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/XMRig%20Monero%20Cryptominer%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/PowerSploit%20IPs.txt",
    "https://raw.githubusercontent.com/montysecurity/C2-Tracker/main/data/Posh%20C2%20IPs.txt",
    "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    "https://cinsscore.com/list/ci-badguys.txt",
    "https://phishing.army/download/phishing_army_blocklist.txt",
    "https://phishing.army/download/phishing_army_blocklist_extended.txt",
    "http://reputation.alienvault.com/reputation.data",
    "https://reputation.alienvault.com/reputation.generic",
    "http://www.talosintelligence.com/documents/ip-blacklist",
    "https://www.binarydefense.com/banlist.txt",
    "https://feeds.ecrimelabs.net/data/metasploit-cve",
    "https://openphish.com/feed.txt",
    "https://cdn.ellio.tech/community-feed",
    "https://osint.digitalside.it/Threat-Intel/lists/latestips.txt",
    "https://osint.digitalside.it/Threat-Intel/lists/latesturls.txt",
    "https://osint.digitalside.it/Threat-Intel/lists/latestdomains.txt",
    "https://urlabuse.com/public/data/data.txt",
    "https://urlabuse.com/public/data/malware_url.txt",
    "https://urlabuse.com/public/data/phishing_url.txt",
    "https://urlabuse.com/public/data/hacked_url.txt",
    "https://nocdn.nrd-list.com/0/nrd-list-32-days.txt",
    "https://nocdn.threat-list.com/0/domains.txt",
    "https://dl.threat-list.com/1/domains.txt",
    "https://threatview.io/Downloads/Experimental-IOC-Tweets.txt",
    "https://threatview.io/Downloads/High-Confidence-CobaltStrike-C2%20-Feeds.txt",
    "https://threatview.io/Downloads/IP-High-Confidence-Feed.txt",
    "https://threatview.io/Downloads/DOMAIN-High-Confidence-Feed.txt",
    "https://threatview.io/Downloads/MD5-HASH-ALL.txt",
    "https://threatview.io/Downloads/URL-High-Confidence-Feed.txt",
    "https://threatview.io/Downloads/SHA-HASH-FEED.txt",
    "https://www.dan.me.uk/torlist/?full",
    "https://www.dan.me.uk/torlist/?exit",
    "https://snort.org/downloads/ip-block-list",
    "https://mirai.security.gives/data/ip_list.txt",
    "https://raw.githubusercontent.com/tsirolnik/spam-domains-list/master/spamdomains.txt"
  ],
  "csv": [
    "https://sslbl.abuse.ch/blacklist/sslblacklist.csv",
    "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
    "https://sslbl.abuse.ch/blacklist/sslipblacklist_aggressive.csv",
    "https://threatfox.abuse.ch/export/csv/md5/recent/",
    "https://threatfox.abuse.ch/export/csv/sha256/recent/",
    "https://urlhaus.abuse.ch/downloads/csv_recent/",
    "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv",
    "https://www.botvrij.eu/data/blocklist/blocklist_domain.csv",
    "https://iocfeed.mrlooquer.com/feed.csv",
    "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv",
    "https://misp.cert.ssi.gouv.fr/feed-misp/hashes.csv",
    "https://hole.cert.pl/domains/domains.csv",
    "https://urlabuse.com/public/data/data_csv.txt"
  ],
  "json": [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "http://data.phishtank.com/data/online-valid.json",
    "https://urlabuse.com/public/data/data.json"
  ]
}

def normalize_ioc(value: str, source: str):
    value = value.strip()
    ioc_type = None
    if not value or value.startswith("#"):
        return None
    try:
        ipaddress.ip_address(value)
        ioc_type = "ip"
    except ValueError:
        if all(c in "0123456789abcdefABCDEF" for c in value) and len(value) in [32, 40, 64]:
            ioc_type = {32: "md5", 40: "sha1", 64: "sha256"}[len(value)]
        elif "." in value and " " not in value:
            ioc_type = "domain"
        else:
            return None
    return {
        "type": ioc_type,
        "value": value,
        "source": source,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

def fetch_plaintext_feed(url):
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        return r.text.splitlines()
    except Exception:
        return []

def fetch_csv_feed(url):
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        reader = csv.reader(StringIO(r.text))
        return [col.strip() for row in reader for col in row if col and not col.startswith("#")]
    except Exception:
        return []

def fetch_json_feed(url):
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
        return r.json()
    except Exception:
        return []

def main():
    ioc_set = set()
    ioc_list = []

    print("Processing plaintext feeds...")
    for url in tqdm(feed_definitions["plaintext"], desc="Plaintext Feeds"):
        for line in fetch_plaintext_feed(url):
            ioc = normalize_ioc(line, url)
            if ioc:
                key = f"{ioc['type']}:{ioc['value']}"
                if key not in ioc_set:
                    ioc_set.add(key)
                    ioc_list.append(ioc)

    print("Processing CSV feeds...")
    for url in tqdm(feed_definitions["csv"], desc="CSV Feeds"):
        for cell in fetch_csv_feed(url):
            ioc = normalize_ioc(cell, url)
            if ioc:
                key = f"{ioc['type']}:{ioc['value']}"
                if key not in ioc_set:
                    ioc_set.add(key)
                    ioc_list.append(ioc)

    
    print("Processing JSON feeds...")
    for url in tqdm(feed_definitions["json"], desc="JSON Feeds"):
        json_data = fetch_json_feed(url)
        if not json_data:
            continue

        if "phish_id" in str(json_data):  # PhishTank
            for entry in json_data:
                url_val = entry.get("url")
                if url_val:
                    ioc = normalize_ioc(url_val, url)
                    if ioc:
                        key = f"{ioc['type']}:{ioc['value']}"
                        if key not in ioc_set:
                            ioc_set.add(key)
                            ioc_list.append(ioc)

        elif isinstance(json_data, dict) and "data" in json_data and isinstance(json_data["data"], list):
            for item in json_data["data"]:
                val = item.get("value") or item.get("ioc") or item.get("url")
                if val:
                    ioc = normalize_ioc(val, url)
                    if ioc:
                        key = f"{ioc['type']}:{ioc['value']}"
                        if key not in ioc_set:
                            ioc_set.add(key)
                            ioc_list.append(ioc)

    output_path = "ioc_feed_output.json"
    with open(output_path, "w") as f:
        json.dump(ioc_list, f, indent=2)
    print(f"Collected {len(ioc_list)} unique IOCs. Output saved to {output_path}")

if __name__ == "__main__":
    main()
