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
for type in types:

    url = f"https://www.cert.ssi.gouv.fr/{type}/feed"
    rss_feed = feedparser.parse(url)

    for entry in rss_feed.entries:
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

        ref_cves = data["cves"]
        #print("CVE référencés ", ref_cves)
        for ref in ref_cves:
            #on recupère le nom de chaque cve
            name = ref["name"]
            url = f"https://cveawg.mitre.org/api/cve/{name}"
            response = requests.get(url)
            data = requests.get(url).json()

            metrics = data["containers"]["cna"].get("metrics", [])
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
            problemtype = data["containers"]["cna"].get("problemTypes", {})
            if problemtype and "descriptions" in problemtype[0]:
                extract_cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
                cwe = extract_cwe if (extract_cwe and extract_cwe != "n/a") else "Non disponible"
                extract_cwe_desc = problemtype[0]["descriptions"][0].get("description", "Non disponible")
                cwe_desc = extract_cwe_desc if (extract_cwe_desc and extract_cwe_desc!="n/a") else "Non disponible"

            affected = data["containers"]["cna"]["affected"]
            vendor="Non disponible"
            product_name = "Non disponible"
            versions = []
            if len(affected) > 0:
                for product in affected:
                    if product["vendor"] and product["vendor"]!="n/a":
                        vendor = product["vendor"]
                    if product["product"] and product["product"]!="n/a":
                        product_name = product["product"]
                    extract_versions = [v["version"] for v in product["versions"] if v["status"] == "affected"]
                    versions = extract_versions if extract_versions and "n/a" not in extract_versions else []

            description = data["containers"]["cna"]["descriptions"][0]["value"]

            url = f"https://api.first.org/data/v1/epss?cve={name}"
            response = requests.get(url)
            data = response.json()
            epss = round(float(data["data"][0]["epss"]), 3)

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
