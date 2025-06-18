
from datetime import datetime
import time

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
max= 2
i=0
try:
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

            ref_cves = list(data.get("cves", []))
            for ref in ref_cves:
                if i > max:
                    break

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
                    for m in metrics:
                        for version_key in ["cvssV3_1", "cvssV3_0", "cvssV2"]:
                            cvss_data = m.get(version_key)
                            if cvss_data:
                                cvss_score = cvss_data.get("baseScore", "Non disponible")
                                cvss_severity = cvss_data.get("baseSeverity", "Non disponible")
                                break
                        if cvss_score != "Non disponible":
                            break

                if cvss_score == "Non disponible" or cvss_severity == "Non disponible":
                    adps = data.get("containers", {}).get("adp", [])

                    for adp in adps:
                        metrics = adp.get("metrics", [])
                        for metric in metrics:
                            for version_key in ["cvssV3_1", "cvssV3_0", "cvssV2"]:
                                cvss = metric.get(version_key)
                                if cvss:
                                    if cvss_score == "Non disponible":
                                        cvss_score = cvss.get("baseScore", "Non disponible")
                                    if cvss_severity == "Non disponible":
                                        cvss_severity = cvss.get("baseSeverity", "Non disponible")
                                    break
                            if cvss_score != "Non disponible" or cvss_severity != "Non disponible":
                                break
                        if cvss_score != "Non disponible" or cvss_severity != "Non disponible":
                            break

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
                percentile = "Non disponible"
                epss_list = resp.get("data", [])
                if epss_list:
                    try:
                        epss = round(float(epss_list[0].get("epss", 0)), 6)
                        percentile = round(float(epss_list[0].get("percentile", 0)), 6)
                    except (TypeError, ValueError):
                        epss = "Non disponible"
                        percentile = "Non disponible"

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
                print("Percentile:", percentile)
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
                    "percentile": percentile,
                    "lien" : link,
                    "description": description,
                    "editeur": vendor,
                    "produit": product_name,
                    "versions": versions
                }
                rows.append(d)
                i+=1
except Exception as e:
    print("Erreur attrapée :", e)

#Etape 4 regrouper toutes les infos dans un tableau
df = pd.DataFrame(rows)
df.to_csv("cve_ansi_enriched_web.csv", index=False)

#Etape 5 faire des graphiques
#Etape 7 Model Machine Learning
# → Aller sur la page html
import webbrowser
print("********************************************************")
print("Voulez vous ouvrir la page html pour voir les étapes 5 et 7 ? (y/n)")
reponse = input().lower()
if reponse == 'y':
    fichier = "visualisation_cve_etape5.html"
    webbrowser.open_new_tab(fichier)
else:
    print("Page non ouverte.")


#Etape 6 Envoyer un mail si une faille est grave
import csv

# Liste d'abonnés (fictifs - on a créé une adresse mail)
subscribers = [
    {"email": "noname.test122333@gmail.com", "editeur": "Microsoft", "product": "Windows Server 2012 R2 (Server Core installation)"},
]
dfs = pd.DataFrame(subscribers)
dfs.to_csv('subscribers.csv', index = False)

def send_email(to_email, subject, body):
    from_email = "noname.test122333@gmail.com"
    password = "wyjkkiclvvezyige"

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email

    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(from_email, password)
    server.sendmail(from_email, to_email, msg.as_string()) 
    server.quit()

alertes = df[df['cvss'] >= 9.0]

for row in alertes.itertuples():
    subject = f"Alerte CVE critique : {row.id}"
    body = (
        f"Alerte de sécurité : {row.title}\n\n"
        f"Produit concerné : {row.produit}\n"
        f"Éditeur : {row.editeur}\n"
        f"Date de l'alerte : {row.date}\n"
        f"Identifiant CVE : {row.cve}\n\n"
        f"Description :\n{row.description}\n\n"
        f"Pour plus d'informations, consultez le lien suivant : {row.lien}\n\n"
        f"Veuillez informer votre service informatique afin qu’il prenne les mesures nécessaires pour corriger cette vulnérabilité."
    )

    abonnes = dfs[(dfs['editeur'] == row.editeur) & (dfs['product'] == row.produit)]

    for dest in abonnes['email']:
        send_email(dest, subject, body)
        print(" Un mail d'alerte a été envoyé à :", dest)
