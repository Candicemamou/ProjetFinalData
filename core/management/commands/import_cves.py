# core/management/commands/import_cves.py

import csv
from datetime import datetime
from django.core.management.base import BaseCommand
from core.models import CVEEntry


class Command(BaseCommand):
    help = 'Importe les données CVE depuis un fichier CSV enrichi'

    def parse_float(self, value):
        try:
            return float(value)
        except (ValueError, TypeError):
            return None

    def add_arguments(self, parser):
        parser.add_argument('csv_file', type=str, help='Chemin vers le fichier CSV')

    def handle(self, *args, **kwargs):
        csv_file = kwargs['csv_file']
        count = 0

        with open(csv_file, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    cve = row['cve']
                    title = row['title']
                    cvss = self.parse_float(row.get('cvss'))
                    epss = self.parse_float(row.get('epss'))
                    percentile = self.parse_float(row.get('percentile'))
                    base_severity = row['base severity'] or None
                    cwe = row['cwe'] or None
                    lien = row['lien']
                    description = row['description']
                    editeur = row['editeur'] or None
                    produit = row['produit'] or None
                    versions = row['versions'] or None

                    try:
                        date = datetime.strptime(row['date'], '%Y-%m-%d').date()
                    except ValueError:
                        date = None

                    CVEEntry.objects.update_or_create(
                        cve=cve,
                        defaults={
                            'title': title,
                            'cvss': cvss,
                            'base_severity': base_severity,
                            'cwe': cwe,
                            'epss': epss,
                            'percentile': percentile,
                            'lien': lien,
                            'description': description,
                            'date': date,
                            'editeur': editeur,
                            'produit': produit,
                            'versions': versions,
                        }
                    )
                    count += 1
                except Exception as e:
                    self.stdout.write(self.style.ERROR(f"Erreur sur {row.get('cve', '')}: {e}"))

        self.stdout.write(self.style.SUCCESS(f"Import de {count} CVEs réussi."))

