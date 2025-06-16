import os
import json

# Dossier contenant les fichiers MITRE
mitre_dir = "./data_pour_TD_final/mitre"
first_dir = "./data_pour_TD_final/first"

cves = [f for f in os.listdir(mitre_dir) if f.endswith(".json")]

for cve_file in cves:
    cve_id = cve_file.replace(".json", "")
    filepath = os.path.join(mitre_dir, cve_file)

    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    cna = data.get("containers", {}).get("cna", {})
    has_cvss = any(
        m.get("cvssV3_1") or m.get("cvssV3_0") or m.get("cvssV2")
        for m in cna.get("metrics", [])
    )
    has_cwe = any(
        pt.get("descriptions", [])
        for pt in cna.get("problemTypes", [])
    )
    has_desc = bool(cna.get("descriptions", []))

    first_path = os.path.join(first_dir, cve_file)
    has_epss = False
    if os.path.exists(first_path):
        with open(first_path, "r", encoding="utf-8") as f:
            epss_data = json.load(f)
        epss_list = epss_data.get("data", [])
        has_epss = bool(epss_list and epss_list[0].get("epss"))

    print(
        f"{cve_id}: CVSS={'✅' if has_cvss else '❌'}, CWE={'✅' if has_cwe else '❌'}, DESC={'✅' if has_desc else '❌'}, EPSS={'✅' if has_epss else '❌'}")
