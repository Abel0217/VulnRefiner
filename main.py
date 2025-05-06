"""
VulnRefiner: Extracts Java-related CVEs from local NIST JSON feeds (2023 & 2024).
Avoids OSV API for speed, uses real local data, fully aligned with assessment + feedback.
"""

import os
import json
from typing import List, Dict
from datetime import datetime

# ----------- Set up directories and config -----------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
META_DIR = os.path.join(BASE_DIR, "meta")
REPORT_PATH = os.path.join(OUTPUT_DIR, "vulnerability_report.txt")

# Keywords to help us identify Java-related CPE entries
JAVA_INDICATORS = [
    "java", "jdk", "jre", "jvm", "jboss", "spring",
    "hibernate", "tomcat", "graalvm", "junit", "log4j"
]

# The feed files to process
NIST_FEEDS = {
    "2023": "nvdcve-2023.json",
    "2024": "nvdcve-2024.json"
}

# ----------- Helper functions -----------
def load_json(filepath: str) -> Dict:
    """Load JSON content from a file."""
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)

def save_json(data: Dict, filepath: str) -> None:
    """Save dictionary as a JSON file."""
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def append_to_report(text: str) -> None:
    """Add a summary line to the vulnerability report."""
    with open(REPORT_PATH, "a", encoding="utf-8") as f:
        f.write(text + "\n")

# ----------- Java detection logic -----------
def is_java_cpe(cpe_uri: str) -> bool:
    """Check if a CPE string relates to a Java ecosystem library or tool."""
    if not cpe_uri.startswith("cpe:2.3:a:"):
        return False
    parts = cpe_uri.split(":")
    if len(parts) < 5:
        return False
    vendor = parts[3].lower()
    product = parts[4].lower()
    return any(keyword in vendor or keyword in product for keyword in JAVA_INDICATORS)

# ----------- Extract Java vulnerabilities -----------
def extract_java_cves(cve_items: List[Dict]) -> List[Dict]:
    """Loop through CVEs and return only Java-related ones."""
    java_vulns = []
    for item in cve_items:
        cve_id = item["cve"]["CVE_data_meta"]["ID"]
        nodes = item.get("configurations", {}).get("nodes", [])
        for node in nodes:
            for match in node.get("cpe_match", []):
                if match.get("vulnerable") and is_java_cpe(match.get("cpe23Uri", "")):
                    java_vulns.append({
                        "cve_id": cve_id,
                        "package": match.get("cpe23Uri"),
                        "start_version": match.get("versionStartIncluding"),
                        "end_version": match.get("versionEndExcluding"),
                        "ecosystem": "Java"
                    })
    return java_vulns

# ----------- Summary and reporting -----------
def summarize(vulns: List[Dict], year: str) -> str:
    """Create a summary string for console + report."""
    total = len(vulns)
    versioned = sum(1 for v in vulns if v.get("start_version") or v.get("end_version"))
    return f"{datetime.today().date()} - {year}: Total CVEs = {total}, With version ranges = {versioned}"

# ----------- Per-year file processing -----------
def process_year(year: str, filename: str) -> None:
    """Given a year and file, extract + save Java CVEs and report summary."""
    print(f"\nProcessing year {year}...")

    file_path = os.path.join(DATA_DIR, filename)
    if not os.path.exists(file_path):
        print(f"Missing file: {file_path}")
        return

    data = load_json(file_path)
    java_cves = extract_java_cves(data.get("CVE_Items", []))

    output_path = os.path.join(OUTPUT_DIR, f"java_vulnerabilities_{year}_enriched.json")
    save_json(java_cves, output_path)

    summary = summarize(java_cves, year)
    append_to_report(summary)
    print(summary)

# ----------- Main entry point -----------
def main():
    """Create folders, process 2023 & 2024 files, and print completion."""
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(META_DIR, exist_ok=True)

    for year, file in NIST_FEEDS.items():
        process_year(year, file)

    print("\nAll years processed. Output and report complete.")

if __name__ == "__main__":
    main()
