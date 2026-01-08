"""
URL configuration for scalekit_django_auth project.
"""
from django.urls import path, include

urlpatterns = [
    path('', include('auth_app.urls')),
]

