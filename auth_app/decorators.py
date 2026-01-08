"""
Custom decorators for authentication and authorization.
"""
from functools import wraps
from django.shortcuts import redirect
from django.http import HttpResponseForbidden
from django.conf import settings
from auth_app.scalekit_client import ScalekitClient


def login_required(view_func):
    """
    Decorator that checks if user is authenticated via Scalekit session.
    Redirects to login if not authenticated.
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.session.get('scalekit_user'):
            from django.urls import reverse
            login_url = reverse('auth_app:login')
            return redirect(f'{login_url}?next={request.path}')
        return view_func(request, *args, **kwargs)
    return _wrapped_view


def permission_required(permission):
    """
    Decorator that checks if user has a specific permission in their access token.
    Uses Scalekit SDK's validate_token method to extract permissions from the token.
    
    Args:
        permission: Permission name required (e.g., 'organization:settings')
    
    Usage:
        @permission_required('organization:settings')
        def my_view(request):
            ...
    """
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            # First check if user is authenticated
            if not request.session.get('scalekit_user'):
                from django.urls import reverse
                login_url = reverse('auth_app:login')
                return redirect(f'{login_url}?next={request.path}')
            
            # Get access token from session
            token_data = request.session.get('scalekit_tokens', {})
            access_token = token_data.get('access_token')
            
            if not access_token:
                return HttpResponseForbidden("No access token found. Please log in again.")
            
            # Check permission using Scalekit SDK
            client = ScalekitClient()
            if not client.has_permission(access_token, permission):
                from django.shortcuts import render
                return render(
                    request,
                    'auth_app/permission_denied.html',
                    {
                        'user': request.session.get('scalekit_user', {}),
                    },
                    status=403
                )
            
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator

