from django.shortcuts import render
from django.core.paginator import Paginator
from core.models import CVEEntry
from django.db.models import Q

def cve_list(request):
    query = request.GET.get('q')
    severity = request.GET.get('severity')
    cves = CVEEntry.objects.all()

    if query:
        cves = cves.filter(Q(title__icontains=query) | Q(cve__icontains=query))
    if severity:
        cves = cves.filter(base_severity__iexact=severity)

    cves = cves.order_by('-date')
    paginator = Paginator(cves, 50)
    page = request.GET.get('page')
    page_obj = paginator.get_page(page)

    return render(request, 'core/cve_list.html', {'page_obj': page_obj})


from django.shortcuts import render, redirect
from .forms import SubscriptionForm

def subscribe(request):
    if request.method == 'POST':
        form = SubscriptionForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('subscribe_success')
    else:
        form = SubscriptionForm()
    return render(request, 'subscribe.html', {'form': form})


def subscribe_success(request):
    return render(request, 'subscribe_success.html')

from django.http import JsonResponse

def get_products(request):
    editeur = request.GET.get('editeur')
    produits = list(
        CVEEntry.objects
        .filter(editeur=editeur)
        .exclude(produit__isnull=True).exclude(produit='')
        .values_list('produit', flat=True)
        .distinct()
        .order_by('produit')
    )
    return JsonResponse({'produits': produits})

def get_severities(request):
    editeur = request.GET.get('editeur')
    produit = request.GET.get('produit')

    severities = (
        CVEEntry.objects.filter(editeur=editeur, produit=produit)
        .values_list('base_severity', flat=True)
        .distinct()
    )
    severities = sorted(set(s for s in severities if s))  # Nettoyage

    return JsonResponse({'severities': severities})


from django.shortcuts import get_object_or_404, redirect
from django.views.decorators.http import require_POST
from django.contrib import messages

@require_POST
def delete_cve(request, pk):
    cve = get_object_or_404(CVEEntry, pk=pk)
    cve.delete()
    messages.success(request, f"{cve.cve} supprimé avec succès.")
    return redirect('cve_list')