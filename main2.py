from datetime import datetime
import os
import json
import pandas as pd

# Paramètres
types = ["alertes", "Avis"]
base_path = "./data_pour_TD_final"
rows = []
max = 3000
i = 0

try:
    for t in types:
        folder_path = os.path.join(base_path, t)
        filenames = sorted(os.listdir(folder_path))

        for filename in filenames:
            if i > max:
                break

            file_path = os.path.join(folder_path, filename)
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            id = data.get("reference", "Non disponible")
            title = data.get("title", "Non disponible")
            date = data.get("revisions", [{}])[-1].get("revision_date", "Non disponible")[:10]
            link = next((l.get("url") for l in data.get("links", []) if l.get("url", "").startswith("https://www.cert.ssi.gouv.fr")), "Non disponible")

            for ref in data.get("cves", []):
                name = ref.get("name")
                if not name:
                    continue

                # Charger les données MITRE locales
                try:
                    with open(os.path.join(base_path, "mitre", f"{name}.json"), "r", encoding="utf-8") as f:
                        mitre_data = json.load(f)
                except:
                    mitre_data = {}

                cna = mitre_data.get("containers", {}).get("cna", {})
                metrics = cna.get("metrics", [])
                cvss_score = "Non disponible"
                cvss_severity = "Non disponible"
                if metrics:
                    for m in metrics:
                        for version_key in ["cvssV3_1", "cvssV3_0", "cvssV2"]:
                            cvss_data = m.get(version_key)
                            if cvss_data:
                                cvss_score = cvss_data.get("baseScore", "Non disponible")
                                cvss_severity = cvss_data.get("baseSeverity", "Non disponible")
                                break
                        if cvss_score != "Non disponible":
                            break

                # CWE et description complète
                cwe_id = "Non disponible"
                cwe_desc = "Non disponible"
                problemtype = cna.get("problemTypes", [])
                for pt in problemtype:
                    for desc in pt.get("descriptions", []):
                        if desc.get("cweId") and desc.get("cweId") != "n/a":
                            cwe_id = desc.get("cweId")
                        if desc.get("description") and desc.get("description") != "n/a":
                            cwe_desc = desc.get("description")
                        break
                    if cwe_desc != "Non disponible":
                        break

                description = "Non disponible"
                for d in cna.get("descriptions", []):
                    if d.get("lang") == "fr":
                        description = d.get("value")
                        break
                if description == "Non disponible" and cna.get("descriptions"):
                    description = cna["descriptions"][0].get("value", "Non disponible")

                # Références supplémentaires (liens associés à la vulnérabilité)
                references = []
                for ref_block in cna.get("references", []):
                    url = ref_block.get("url")
                    if url:
                        references.append(url)

                # Charger les données FIRST locales (EPSS)
                try:
                    with open(os.path.join(base_path, "first", f"{name}.json"), "r", encoding="utf-8") as f:
                        epss_data = json.load(f)
                    epss_list = epss_data.get("data", [])
                    epss = round(float(epss_list[0].get("epss", 0)), 6) if epss_list else "Non disponible"
                except:
                    epss = "Non disponible"

                # Infos produit/éditeur (ANSSI)
                vendors = []
                products = []
                versions = []
                for p in data.get("affected_systems", []):
                    vendor = p.get("product", {}).get("vendor", {}).get("name")
                    if vendor and vendor not in vendors:
                        vendors.append(vendor)
                    pname = p.get("product", {}).get("name")
                    if pname and pname not in products:
                        products.append(pname)
                    desc = p.get("description")
                    if desc and desc not in versions:
                        versions.append(desc)

                print(f"\nID ANSSI: {id}\nTitre: {title}\nType: {t}\nDate: {date}\nCVE: {name}\nCVSS: {cvss_score}\nBase Severity: {cvss_severity}\nCWE ID: {cwe_id}\nCWE Desc: {cwe_desc}\nEPSS: {epss}\nLien: {link}\nDescription: {description}\nRéférences: {references}\nÉditeur: {', '.join(vendors)}\nProduit: {', '.join(products)}\nVersions: {versions}\n------------------------------")

                d = {
                    "id": id,
                    "title": title,
                    "type": t,
                    "date": date,
                    "cve": name,
                    "cvss": cvss_score,
                    "base severity": cvss_severity,
                    "cwe id": cwe_id,
                    "cwe": cwe_desc,
                    "epss": epss,
                    "lien": link,
                    "description": description,
                    "references": "; ".join(references),
                    "editeur": ", ".join(vendors),
                    "produit": ", ".join(products),
                    "versions": "; ".join(versions)
                }
                rows.append(d)
                i += 1

except Exception as e:
    print("Erreur attrapée :", e)

# Export CSV
df = pd.DataFrame(rows)
df.to_csv("cve_ansi_enriched_local.csv", index=False)
