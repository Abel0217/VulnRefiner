import os
import sys
import json
import pytest

# Ensure we can import from the parent directory
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from main import is_java_cpe, extract_java_cves, summarize

# ----------------- Fixtures -----------------

@pytest.fixture
def sample_cve_data():
    return {
        "CVE_Items": [
            {
                "cve": {
                    "CVE_data_meta": {
                        "ID": "CVE-2023-9999"
                    }
                },
                "configurations": {
                    "nodes": [
                        {
                            "cpe_match": [
                                {
                                    "vulnerable": True,
                                    "cpe23Uri": "cpe:2.3:a:apache:tomcat:9.0:*:*:*:*:*:*:*",
                                    "versionStartIncluding": "9.0.0",
                                    "versionEndExcluding": "9.0.45"
                                },
                                {
                                    "vulnerable": True,
                                    "cpe23Uri": "cpe:2.3:a:mozilla:firefox:90.0:*:*:*:*:*:*:*"
                                }
                            ]
                        }
                    ]
                }
            }
        ]
    }

# ----------------- Test is_java_cpe -----------------

def test_is_java_cpe_positive():
    assert is_java_cpe("cpe:2.3:a:apache:tomcat:9.0:*:*:*:*:*:*:*") == True

def test_is_java_cpe_negative_non_java():
    assert is_java_cpe("cpe:2.3:a:mozilla:firefox:90.0:*:*:*:*:*:*:*") == False

def test_is_java_cpe_malformed():
    assert is_java_cpe("invalid_string") == False

# ----------------- Test extract_java_cves -----------------

def test_extract_java_cves_returns_expected_format(sample_cve_data):
    extracted = extract_java_cves(sample_cve_data["CVE_Items"])
    assert len(extracted) == 1
    assert extracted[0]["cve_id"] == "CVE-2023-9999"
    assert extracted[0]["package"].startswith("cpe:2.3:a:apache:tomcat")
    assert extracted[0]["start_version"] == "9.0.0"
    assert extracted[0]["end_version"] == "9.0.45"
    assert extracted[0]["ecosystem"] == "Java"

# ----------------- Test summarize -----------------

def test_summarize_returns_correct_summary():
    test_vulns = [
        {"cve_id": "CVE-2023-0001", "start_version": None, "end_version": None},
        {"cve_id": "CVE-2023-0002", "start_version": "1.0.0", "end_version": "1.2.0"}
    ]
    summary = summarize(test_vulns, "2023")
    assert "Total CVEs = 2" in summary
    assert "With version ranges = 1" in summary
