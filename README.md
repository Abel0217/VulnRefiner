# VulnRefiner

VulnRefiner is a Python-based tool that extracts and processes Java-related vulnerabilities (CVEs) from the official NIST feeds (2023 and 2024). It is designed to enrich vulnerability databases without relying on third-party APIs, making it suitable for offline analysis and efficient security workflows.

---

## Project Overview

This tool processes large vulnerability datasets and isolates only Java-related CVEs, extracting the version ranges in which each package is vulnerable. It outputs both enriched JSON files and a plain-text report, offering a clean foundation for integration into larger security platforms or internal tools.

---

## Installation

```bash
# Clone the repository
git clone https://github.com/Abel0217/vulnrefiner.git
cd vulnrefiner

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

---

## Running Tests

The project includes unit tests using pytest:

```bash
pytest
```

Tests cover:
- CPE detection logic for Java packages
- CVE extraction from feed files
- Summary generation and formatting

---

## Usage

1. Place the official NIST JSON feeds into the `data/` directory:
   - `nvdcve-2023.json`
   - `nvdcve-2024.json`

2. Run the script:

```bash
python main.py
```

3. Output:
   - Enriched JSONs will be saved in `output/`
   - Summary logs are written to `vulnerability_report.txt`

---

## Design Decisions

- Single-script architecture simplifies deployment and understanding.
- Local-only data enrichment reduces dependency risk and improves speed.
- Real Java CVE detection is based on vendor and product patterns in CPEs.
- Output is structured and consistent for easy downstream use.

---

## Use of AI Tools

Some development steps were supported using AI tools to accelerate routine coding tasks, improve structural decisions, and validate certain logic patterns. All core logic and structure were independently reviewed and edited to ensure clarity and maintainability. AI was used strictly as a support tool, similar to referencing documentation or technical forums.

---

## Project Structure

```
vulnrefiner/
├── data/
│   ├── nvdcve-2023.json
│   └── nvdcve-2024.json
├── output/
│   ├── java_vulnerabilities_2023_enriched.json
│   ├── java_vulnerabilities_2024_enriched.json
│   └── vulnerability_report.txt
├── tests/
│   └── test_main.py
├── main.py
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Contact

Feel free to connect via GitHub for questions or collaborations.
