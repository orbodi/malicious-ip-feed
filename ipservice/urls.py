"""
URL configuration for ipservice project.
"""
from django.contrib import admin
from django.urls import path

from ipfeed import views as ipfeed_views

urlpatterns = [
    path("", ipfeed_views.landing, name="landing"),
    path("health/", ipfeed_views.health, name="health"),
    path("malicious-ips/", ipfeed_views.malicious_ips, name="malicious_ips"),
    path("dashboard/", ipfeed_views.dashboard, name="dashboard"),
    path("admin/", admin.site.urls),
]
