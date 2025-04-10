#!/usr/bin/env python3
# tools/3rdparty.py
#
# Script to fetch DNS RR types from IANA and convert to JSON for analyzer-d4-passivedns.
#
# Copyright (c) 2025 (Your Name or Organization)
# Licensed under GNU Affero General Public License v3.

import csv
import json
import requests
from pathlib import Path

# URL of the IANA DNS RR types CSV
IANA_URL = (
    "https://www.iana.org/assignments/dns-parameters/dns-parameters-4.csv"  # 20/03/2025
)
OUTPUT_FILE = Path(__file__).parent.parent / "config" / "rrtypes.json"


def fetch_and_convert():
    """Fetch the IANA CSV and convert it to JSON."""
    try:
        # Fetch the CSV
        response = requests.get(IANA_URL)
        response.raise_for_status()
        csv_content = response.text

        # Parse CSV
        rrset = []
        csv_reader = csv.DictReader(csv_content.splitlines())
        for row in csv_reader:
            # Clean and standardize the row
            record = {
                "Reference": row.get("Reference", "").strip(),
                "Type": row.get("TYPE", "").strip(),
                "Value": row.get("Value", "").strip(),
                "Meaning": row.get("Meaning", "").strip(),
                "Template": row.get("Template", "").strip(),
                "Registration Date": row.get("Registration Date", "").strip(),
            }
            # Skip invalid rows (e.g., missing Type or Value)
            if record["Type"] and record["Value"].isdigit():
                rrset.append(record)

        # Write to JSON file
        OUTPUT_FILE.parent.mkdir(exist_ok=True)  # Ensure config/ exists
        with open(OUTPUT_FILE, "w") as f:
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
