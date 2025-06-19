from django.db import models

class CVEEntry(models.Model):
    cve = models.CharField(max_length=50, unique=True)
    title = models.TextField()
    date = models.DateField(null=True, blank=True)
    cvss = models.FloatField(null=True, blank=True)
    base_severity = models.CharField(max_length=20, null=True, blank=True)
    cwe = models.CharField(max_length=200, null=True, blank=True)
    epss = models.FloatField(null=True, blank=True)
    percentile = models.FloatField(null=True, blank=True)
    lien = models.URLField(null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    editeur = models.CharField(max_length=100, null=True, blank=True)
    produit = models.CharField(max_length=100, null=True, blank=True)
    versions = models.TextField(null=True, blank=True)

    def __str__(self):
        return f"{self.cve} - {self.title[:50]}"

class Subscriber(models.Model):
    email = models.EmailField(unique=True)

    def __str__(self):
        return self.email

SEVERITY_CHOICES = [
    ("LOW", "Low"),
    ("MEDIUM", "Medium"),
    ("HIGH", "High"),
    ("CRITICAL", "Critical"),
]

class Subscription(models.Model):
    email = models.EmailField()
    editeur = models.CharField(max_length=200, blank=True, null=True)
    produit = models.CharField(max_length=200, blank=True, null=True)


class AlertHistory(models.Model):
    subscription = models.ForeignKey(Subscription, on_delete=models.CASCADE)
    cve = models.ForeignKey(CVEEntry, on_delete=models.CASCADE)
    sent_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("subscription", "cve")

    def __str__(self):
        return f"{self.subscription.email} - {self.cve.cve}"