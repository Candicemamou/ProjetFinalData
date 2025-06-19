from django.urls import path
from . import views
from .views import subscribe

urlpatterns = [
    path('', views.cve_list, name='cve_list'),
    path('subscribe/', subscribe, name='subscribe'),
]