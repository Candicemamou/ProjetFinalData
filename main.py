from datetime import datetime

#Etape 1 recuperer les actualités de sécurité
import feedparser
import requests
import re
import pandas as pd
from math import *
import matplotlib.pyplot as plt
import smtplib
from email.mime.text import MIMEText


types=["alerte", "avis"]
rows=[]

#On recupère tous les types possibles.
max= 150
i=0
for type in types:
    if i > max:
        break
    url = f"https://www.cert.ssi.gouv.fr/{type}/feed"
    rss_feed = feedparser.parse(url)

    for entry in rss_feed.entries:
        if i > max:
            break

        id = entry.id.replace(f"https://www.cert.ssi.gouv.fr/{type}/", "").replace("/", "")
        title = entry.title
        t = type
        raw_date = entry.published
        date_obj = datetime.strptime(raw_date, "%a, %d %b %Y %H:%M:%S %z")
        date = date_obj.strftime("%Y-%m-%d")
        link = entry.link

        url_cves = f"https://www.cert.ssi.gouv.fr/{type}/{id}/json/"
        response = requests.get(url_cves)
        data = response.json()

        ref_cves = data.get("cves", [])
        #print("CVE référencés ", ref_cves)
        for ref in ref_cves:
            #on recupère le nom de chaque cve
            name = ref.get("name")
            if not name:
                continue
            url = f"https://cveawg.mitre.org/api/cve/{name}"
            response = requests.get(url)
            data = requests.get(url).json()

            cna = data.get("containers", {}).get("cna", {})
            metrics = cna.get("metrics", [])
            cvss_score = "Non disponible"
            cvss_severity = "Non disponible"
            if metrics:
                cvss_data = metrics[0].get("cvssV3_0")
                if cvss_data:
                    cvss_score = cvss_data.get("baseScore", "Non disponible")
                    cvss_severity = cvss_data.get("baseSeverity", "Non disponible")
                elif metrics[0].get("cvssV3_1"):
                    cvss_data = metrics[0].get("cvssV3_1")
                    cvss_score = cvss_data.get("baseScore", "Non disponible")
                    cvss_severity = cvss_data.get("baseSeverity", "Non disponible")

            cwe = "Non disponible"
            cwe_desc = "Non disponible"
            problemtype = cna.get("problemTypes", {})
            if problemtype and "descriptions" in problemtype[0]:
                extract_cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
                cwe = extract_cwe if (extract_cwe and extract_cwe != "n/a") else "Non disponible"
                extract_cwe_desc = problemtype[0]["descriptions"][0].get("description", "Non disponible")
                cwe_desc = extract_cwe_desc if (extract_cwe_desc and extract_cwe_desc!="n/a") else "Non disponible"

            affected = cna.get("affected", [])
            vendor = "Non disponible"
            product_name = "Non disponible"
            versions = []

            if affected:
                for p in affected:
                    raw_vendor = p.get("vendor")
                    if isinstance(raw_vendor, dict):
                        candidate = raw_vendor.get("name")
                    else:
                        candidate = raw_vendor
                    if candidate and candidate.lower() != "n/a":
                        vendor = candidate

                    raw_prod = p.get("product")
                    if isinstance(raw_prod, dict):
                        candidate = raw_prod.get("name")
                    else:
                        candidate = raw_prod
                    if candidate and candidate.lower() != "n/a":
                        product_name = candidate

                    versions = [
                        v.get("version", "Non disponible")
                        for v in p.get("versions", [])
                        if v.get("status") == "affected"
                           and v.get("version", "").lower() != "n/a"
                    ]

            descs = cna.get("descriptions", [])

            if descs and isinstance(descs[0], dict):
                description = descs[0].get("value", "Non disponible")
            else:
                description = "Non disponible"

            url = f"https://api.first.org/data/v1/epss?cve={name}"
            resp = requests.get(url).json()

            epss = "Non disponible"
            epss_list = resp.get("data", [])
            if epss_list:
                val = epss_list[0].get("epss")
                try:
                    epss = round(float(val), 3)
                except (TypeError, ValueError):
                    epss = "Non disponible"

            print("")
            print("ID ANSSI:",id)
            print("Titre ANSSI:",title)
            print("Type:",t)
            print("Date:",date)
            print("CVE:", name)
            print("CVSS:", cvss_score)
            print("Base Severity:", cvss_severity)
            print("CWE:", cwe_desc)
            print("EPSS:", epss)
            print("Lien:",link)
            print("Description:",description)
            print("Editeur:", vendor)
            print("Produit:", product_name)
            print("Versions affectées:", versions)
            print("")
            print("------------------------------")

            d = {
                "id": id,
                "title": title,
                "type": t,
                "date": date,
                "cve": name,
                "cvss" : cvss_score,
                "base severity": cvss_severity,
                "cwe": cwe_desc,
                "epss": epss,
                "lien" : link,
                "description": description,
                "editeur": vendor,
                "produit": product_name,
                "versions": versions
            }
            rows.append(d)
            i+=1



#Etape 4 regrouper toutes les infos dans un tableau
df = pd.DataFrame(rows)
df.to_csv("cve_ansi_enriched.csv", index=False)


#Etape 5 faire des graphiques
'''
df['CVSS'].hist()
plt.title("Distribution des scores CVSS")
plt.show()

#Etape 6 Envoyer un mail si une faille est grave
#Exemple de code pour l'envoi d'email :

def send_email(to_email, subject, body):
    from_email = "ton_email@gmail.com"
    password = "ton_mot_de_passe"

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email

    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(from_email, password)
    server.sendmail(from_email, to_email, msg.as_string())
    server.quit()
'''
