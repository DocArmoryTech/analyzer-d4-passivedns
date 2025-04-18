#!/usr/bin/env python3
# tools/3rdparty.py
"""Fetch DNS RR types from IANA and convert to JSON for analyzer-d4-passivedns."""
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import csv
import json
from pathlib import Path

IANA_URL = "https://www.iana.org/assignments/dns-parameters/dns-parameters-4.csv"
OUTPUT_FILE = Path(__file__).parent.parent / "config" / "rrtypes.json"

def fetch_and_convert():
    """Fetch IANA DNS RR types CSV and convert to JSON."""
    session = requests.Session()
    retry_strategy = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retry_strategy))

    try:
        response = session.get(IANA_URL, timeout=10)
        response.raise_for_status()
        csv_content = response.text

        rrset = []
        csv_reader = csv.DictReader(csv_content.splitlines())
        for row in csv_reader:
            record = {k: v.strip() for k, v in row.items() if k}
            if record.get("Type") and record.get("Value") and record["Value"].isdigit():
                rrset.append(record)
            else:
                logger.warning(f"Skipping invalid CSV row: {row}")

        if not rrset:
            raise ValueError("No valid RR types found in IANA CSV")

        OUTPUT_FILE.parent.mkdir(exist_ok=True)
        with OUTPUT_FILE.open("w") as f:
            json.dump(rrset, f, indent=4)
        print(f"Successfully wrote {len(rrset)} RR types to {OUTPUT_FILE}")
    except requests.RequestException as e:
        print(f"Failed to fetch IANA CSV: {e}")
        exit(1)
    except Exception as e:
        print(f"Error processing CSV or writing JSON: {e}")
        exit(1)

if __name__ == "__main__":
    fetch_and_convert()