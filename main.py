
#Etape 1 recuperer les actualités de sécurité
import feedparser

url = "https://www.cert.ssi.gouv.fr/avis/feed"  # ou "https://www.cert.ssi.gouv.fr/alerte/feed"
rss_feed = feedparser.parse(url)

for entry in rss_feed.entries:
    print("Titre :", entry.title)
    print("Lien :", entry.link)

#Etape 2  trouver les failles CVE dans chaque bulletin

import requests
import re

url = "https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-001/json/"
response = requests.get(url)
data = response.json()

# Méthode 1 : directement via la clé "cves"
ref_cves = data["cves"]

# Méthode 2 : avec une expression régulière (regex)
cve_pattern = r"CVE-\d{4}-\d{4,7}"
cve_list = list(set(re.findall(cve_pattern, str(data))))

#Etape 3 compléter les infos de CVE grâce à des API

# Exemple pour MITRE
cve_id = "CVE-2023-24488"
url = f"https://cveawg.mitre.org/api/cve/{cve_id}"
data = requests.get(url).json()

description = data["containers"]["cna"]["descriptions"][0]["value"]
cvss_score = data["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseScore"]

#Etape 4 regrouper toutes les infos dans un tableau

import pandas as pd

df = pd.DataFrame([
    {
        "ID": "CERTFR-2024-ALE-001",
        "CVE": "CVE-2023-24488",
        "CVSS": 9.8,
        "EPSS": 0.9,
        "Produit": "Apache",
        "Description": "Faille critique dans Apache...",
        # etc.
    }
])

#Etape 5 faire des graphiques
import matplotlib.pyplot as plt

df['CVSS'].hist()
plt.title("Distribution des scores CVSS")
plt.show()

#Etape 6 Envoyer un mail si une faille est grave
import smtplib
from email.mime.text import MIMEText

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

