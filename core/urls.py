from django.urls import path
from . import views
from .views import subscribe

urlpatterns = [
    path('', views.cve_list, name='cve_list'),
    path('subscribe/', views.subscribe, name='subscribe'),
    path('subscribe/success/', views.subscribe_success, name='subscribe_success'),
    path('get-products/', views.get_products, name='get_products'),
    path('get-severities/', views.get_severities, name='get_severities'),
    path('delete/<int:pk>/', views.delete_cve, name='delete_cve'),
]