from django import forms
from .models import Subscription, CVEEntry

# core/forms.py
class SubscriptionForm(forms.ModelForm):
    class Meta:
        model = Subscription
        fields = ['email', 'editeur', 'produit']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        editeurs = (
            CVEEntry.objects
            .exclude(editeur__isnull=True).exclude(editeur='')
            .values_list('editeur', flat=True).distinct().order_by('editeur')
        )
        self.fields['editeur'].widget = forms.Select(
            choices=[('', '--- Choisir un éditeur ---')] + [(e, e) for e in editeurs]
        )
        self.fields['produit'].widget = forms.Select(choices=[('', '--- Sélectionner un éditeur d’abord ---')])