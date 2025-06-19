import time
from django.core.management.base import BaseCommand
from core.models import CVEEntry, Subscription, AlertHistory
from core.utils.email import send_email
from django.utils import timezone


class Command(BaseCommand):
    help = "Envoie les alertes CVE critiques personnalisées toutes les 30 minutes"

    def handle(self, *args, **kwargs):
        print("Lancement de la vérification continue des CVEs...")
        while True:
            self.check_and_notify()
            print("Attente de 30 minutes avant la prochaine vérification...")
            time.sleep(1800)

    def check_and_notify(self):
        alertes = CVEEntry.objects.filter(cvss__gte=9.0)

        for subscription in Subscription.objects.all():
            for cve in alertes:
                if (
                    (not subscription.editeur or subscription.editeur == cve.editeur)
                    and (not subscription.produit or subscription.produit == cve.produit)
                    and not AlertHistory.objects.filter(subscription=subscription, cve=cve).exists()
                ):
                    subject = f"Alerte critique : {cve.cve}"
                    body = (
                        f"Titre : {cve.title}\n"
                        f"Produit : {cve.produit or 'N/A'}\n"
                        f"Éditeur : {cve.editeur or 'N/A'}\n"
                        f"Date : {cve.date}\n"
                        f"Score CVSS : {cve.cvss}\n"
                        f"\nLien : {cve.lien or 'Aucun lien'}\n\n"
                        f"Description :\n{cve.description}\n"
                    )
                    try:
                        send_email(subscription.email, subject, body)
                        AlertHistory.objects.create(subscription=subscription, cve=cve)
                        print(f"✅ Mail envoyé à {subscription.email} pour {cve.cve}")
                    except Exception as e:
                        print(f"❌ Erreur lors de l'envoi à {subscription.email}: {e}")