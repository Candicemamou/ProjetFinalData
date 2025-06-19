import logging
from core.models import CVEEntry, Subscription
from core.utils.email import send_email

def check_for_alerts():
    print("[✔] Démarrage de la vérification des alertes…")

    alertes = CVEEntry.objects.filter(cvss__gte=9.0)
    if not alertes.exists():
        print("[ℹ] Aucune nouvelle alerte critique détectée.")
        return

    for row in alertes:
        abonnements = Subscription.objects.filter(
            editeur__iexact=row.editeur,
            produit__iexact=row.produit
        )

        for sub in abonnements:
            body = (
                f"Alerte critique sur {row.produit} ({row.editeur})\n\n"
                f"CVE: {row.cve}\n"
                f"Score CVSS: {row.cvss}\n"
                f"Description: {row.description}\n"
                f"Date: {row.date}\n"
                f"→ {row.lien}\n"
            )
            send_email(sub.email, f"[ALERTE] {row.title[:60]}", body)
            print(f"[📨] Email envoyé à {sub.email} pour {row.cve}")