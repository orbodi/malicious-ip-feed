from django.urls import path

from . import views

urlpatterns = [
    path("", views.landing, name="landing"),
    path("health/", views.health, name="health"),
    path("malicious-ips/", views.malicious_ips, name="malicious_ips"),
    path("dashboard/", views.dashboard, name="dashboard"),
]
