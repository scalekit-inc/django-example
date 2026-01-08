"""
URL configuration for auth_app.
"""
from django.urls import path
from . import views

app_name = 'auth_app'

urlpatterns = [
    # Public routes
    path('', views.home_view, name='home'),
    path('login/', views.login_view, name='login'),
    # Callback without trailing slash to avoid redirect issues
    path('auth/callback', views.callback_view, name='callback'),
    
    # Protected routes
    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('logout/', views.logout_view, name='logout'),
    
    # Session management routes
    path('sessions/', views.sessions_view, name='sessions'),
    path('sessions/validate-token/', views.validate_token_view, name='validate_token'),
    path('sessions/refresh-token/', views.refresh_token_view, name='refresh_token'),
    
    # Permission-protected routes
    path('organization/settings/', views.organization_settings_view, name='organization_settings'),
]
