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
from .forms import SubscriberForm

def subscribe(request):
    if request.method == 'POST':
        form = SubscriberForm(request.POST)
        if form.is_valid():
            form.save()
            return render(request, 'subscribe_success.html')
    else:
        form = SubscriberForm()
    return render(request, 'subscribe.html', {'form': form})