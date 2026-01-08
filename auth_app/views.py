"""
Views for Scalekit authentication and authorization.
Uses session-based storage for authentication state.
"""
import logging
import secrets
import json
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponseForbidden
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from auth_app.scalekit_client import scalekit_client
from auth_app.decorators import login_required, permission_required

logger = logging.getLogger(__name__)


def home_view(request):
    """
    Home page with login option.
    Route: /
    """
    # If user is already authenticated, redirect to dashboard
    if request.session.get('scalekit_user'):
        return redirect('auth_app:dashboard')
    
    return render(request, 'auth_app/index.html')


def login_view(request):
    """
    Custom login page.
    Route: /login
    """
    # If user is already authenticated, redirect to dashboard
    if request.session.get('scalekit_user'):
        return redirect('auth_app:dashboard')
    
    # Generate state parameter for CSRF protection
    state = secrets.token_urlsafe(32)
    request.session['oauth_state'] = state
    request.session.save()  # Explicitly save session to ensure state is persisted
    
    # Get authorization URL from Scalekit
    client = scalekit_client()
    auth_url = client.get_authorization_url(state=state)
    
    logger.debug(f"Generated OAuth state: {state[:10]}... (stored in session)")
    
    context = {
        'auth_url': auth_url,
    }
    
    return render(request, 'auth_app/login.html', context)


def callback_view(request):
    """
    Handle OAuth 2.0 callback from Scalekit.
    Route: /auth/callback
    """
    # Verify state parameter
    state = request.GET.get('state')
    stored_state = request.session.get('oauth_state')
    
    logger.debug(f"Callback received state: {state[:10] if state else 'None'}...")
    logger.debug(f"Stored state in session: {stored_state[:10] if stored_state else 'None'}...")
    
    if not state or state != stored_state:
        logger.error(f"OAuth state mismatch - received: {state}, stored: {stored_state}")
        return render(request, 'auth_app/error.html', {
            'error': 'Invalid state parameter. Please try logging in again. Make sure cookies are enabled.'
        }, status=400)
    
    # Clear state from session
    request.session.pop('oauth_state', None)
    
    # Get authorization code
    code = request.GET.get('code')
    error = request.GET.get('error')
    
    if error:
        logger.error(f"OAuth error: {error}")
        return render(request, 'auth_app/error.html', {
            'error': f'Authentication failed: {error}'
        }, status=400)
    
    if not code:
        return render(request, 'auth_app/error.html', {
            'error': 'No authorization code received.'
        }, status=400)
    
    try:
        # Exchange code for tokens
        client = scalekit_client()
        token_response = client.exchange_code_for_tokens(code)
        
        access_token = token_response.get('access_token')
        refresh_token = token_response.get('refresh_token')
        id_token = token_response.get('id_token')
        expires_in = token_response.get('expires_in', 3600)
        
        # Log token response for debugging
        logger.debug(f"Token response keys: {list(token_response.keys())}")
        logger.debug(f"Has refresh_token: {bool(refresh_token)}")
        
        # Get user information
        user_info = client.get_user_info(access_token)
        
        # Store user and token information in session (no database)
        expires_at = timezone.now() + timedelta(seconds=expires_in)
        request.session['scalekit_user'] = {
            'sub': user_info.get('sub'),
            'email': user_info.get('email'),
            'name': user_info.get('name'),
            'given_name': user_info.get('given_name'),
            'family_name': user_info.get('family_name'),
            'preferred_username': user_info.get('preferred_username'),
            'claims': user_info,  # Store all claims
        }
        request.session['scalekit_tokens'] = {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'id_token': id_token,
            'expires_at': expires_at.isoformat(),
            'expires_in': expires_in,
        }
        
        # Extract roles and permissions from user info
        roles = user_info.get('roles', []) or user_info.get('https://scalekit.com/roles', [])
        permissions = user_info.get('permissions', []) or user_info.get('https://scalekit.com/permissions', [])
        request.session['scalekit_roles'] = roles
        request.session['scalekit_permissions'] = permissions
        
        logger.info(f"User {user_info.get('email')} authenticated successfully via Scalekit")
        
        # Redirect to dashboard
        return redirect('auth_app:dashboard')
        
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        return render(request, 'auth_app/error.html', {
            'error': f'Authentication failed: {str(e)}'
        }, status=500)


@login_required
def dashboard_view(request):
    """
    Protected dashboard page.
    Route: /dashboard
    """
    user_data = request.session.get('scalekit_user', {})
    token_data = request.session.get('scalekit_tokens', {})
    roles = request.session.get('scalekit_roles', [])
    permissions = request.session.get('scalekit_permissions', [])
    
    # Parse expires_at
    expires_at = None
    if token_data.get('expires_at'):
        try:
            expires_at = timezone.datetime.fromisoformat(token_data['expires_at'].replace('Z', '+00:00'))
        except:
            pass
    
    context = {
        'user': user_data,
        'name': user_data.get('name', 'User'),
        'email': user_data.get('email', ''),
        'subject': user_data.get('sub', ''),
        'claims': user_data.get('claims', {}),
        'roles': roles,
        'permissions': permissions,
        'token_expires_at': expires_at,
        'has_access_token': bool(token_data.get('access_token')),
        'has_refresh_token': bool(token_data.get('refresh_token')),
    }
    
    return render(request, 'auth_app/dashboard.html', context)


@login_required
def logout_view(request):
    """
    Logout the user from both Django and Scalekit.
    Route: /logout
    """
    token_data = request.session.get('scalekit_tokens', {})
    access_token = token_data.get('access_token')
    
    # Get logout URL from Scalekit SDK
    if access_token:
        try:
            client = scalekit_client()
            logout_url = client.logout(access_token)
            # Redirect to Scalekit logout URL instead of just clearing session
            # This ensures proper logout on Scalekit side
            request.session.flush()
            return redirect(logout_url)
        except Exception as e:
            logger.error(f"Error during Scalekit logout: {e}")
    
    # Clear all session data
    request.session.flush()
    
    logger.info("User logged out")
    
    return redirect('auth_app:home')


# Session Management endpoints
@login_required
def sessions_view(request):
    """
    Display current session information.
    Route: /sessions
    """
    user_data = request.session.get('scalekit_user', {})
    token_data = request.session.get('scalekit_tokens', {})
    
    # Calculate token expiry info
    expires_at = None
    minutes_until_expiry = None
    is_expired = False
    is_expiring_soon = False
    
    if token_data.get('expires_at'):
        try:
            expires_at = timezone.datetime.fromisoformat(token_data['expires_at'].replace('Z', '+00:00'))
            now = timezone.now()
            if expires_at.tzinfo is None:
                expires_at = timezone.make_aware(expires_at)
            
            delta = expires_at - now
            minutes_until_expiry = int(delta.total_seconds() / 60)
            is_expired = delta.total_seconds() < 0
            is_expiring_soon = 0 <= minutes_until_expiry <= 5
        except Exception as e:
            logger.error(f"Error parsing expires_at: {e}")
    
    context = {
        'user': user_data,
        'session_info': {
            'userId': user_data.get('sub'),
            'email': user_data.get('email'),
            'name': user_data.get('name'),
            'hasAccessToken': bool(token_data.get('access_token')),
            'hasRefreshToken': bool(token_data.get('refresh_token')),
        },
        'expiry_info': {
            'expiresAt': expires_at,
            'minutesUntilExpiry': minutes_until_expiry,
            'isExpired': is_expired,
            'isExpiringSoon': is_expiring_soon,
        },
        'is_token_expired': is_expired,
        'is_token_expiring_soon': is_expiring_soon,
        # Token values for display
        'access_token': token_data.get('access_token', ''),
        'refresh_token': token_data.get('refresh_token', ''),
        'id_token': token_data.get('id_token', ''),
    }
    
    return render(request, 'auth_app/sessions.html', context)


@login_required
def validate_token_view(request):
    """
    Validate the current access token (API endpoint).
    Route: /sessions/validate-token (POST)
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    token_data = request.session.get('scalekit_tokens', {})
    access_token = token_data.get('access_token')
    
    if not access_token:
        return JsonResponse({
            'valid': False,
            'error': 'No access token found'
        })
    
    try:
        client = scalekit_client()
        user_info = client.get_user_info(access_token)
        
        return JsonResponse({
            'valid': True,
            'claims': user_info,
            'message': 'Token is valid',
            'userId': user_info.get('sub'),
            'email': user_info.get('email'),
            'name': user_info.get('name'),
        })
    except Exception as e:
        logger.error(f"Token validation error: {e}")
        return JsonResponse({
            'valid': False,
            'error': f'Token validation failed: {str(e)}'
        })


@login_required
def refresh_token_view(request):
    """
    Refresh the access token (API endpoint).
    Route: /sessions/refresh-token (POST)
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    token_data = request.session.get('scalekit_tokens', {})
    refresh_token = token_data.get('refresh_token')
    
    logger.debug(f"Token data keys in session: {list(token_data.keys()) if token_data else 'No token data'}")
    logger.debug(f"Refresh token present: {bool(refresh_token)}")
    
    if not refresh_token:
        return JsonResponse({
            'success': False,
            'error': 'No refresh token available. Make sure you requested the "offline_access" scope during authentication.'
        })
    
    try:
        client = scalekit_client()
        token_response = client.refresh_access_token(refresh_token)
        
        # Update session with new tokens
        expires_in = token_response.get('expires_in', 3600)
        expires_at = timezone.now() + timedelta(seconds=expires_in)
        
        request.session['scalekit_tokens'] = {
            'access_token': token_response.get('access_token'),
            'refresh_token': token_response.get('refresh_token', refresh_token),  # Keep old if not provided
            'id_token': token_response.get('id_token', token_data.get('id_token')),
            'expires_at': expires_at.isoformat(),
            'expires_in': expires_in,
        }
        
        return JsonResponse({
            'success': True,
            'message': 'Tokens refreshed successfully',
            'newAccessToken': token_response.get('access_token'),
            'newRefreshToken': token_response.get('refresh_token'),
            'newIdToken': token_response.get('id_token'),
        })
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        return JsonResponse({
            'success': False,
            'error': f'Token refresh failed: {str(e)}'
        })


@permission_required('organization:settings')
def organization_settings_view(request):
    """
    Protected organization settings page.
    Requires 'organization:settings' permission in the access token.
    Route: /organization/settings
    """
    user_data = request.session.get('scalekit_user', {})
    token_data = request.session.get('scalekit_tokens', {})
    
    # Get access token to validate and show permissions
    access_token = token_data.get('access_token')
    client = scalekit_client()
    
    # Get token claims to show permissions
    claims = {}
    permissions = []
    if access_token:
        try:
            claims = client.validate_token_and_get_claims(access_token)
            permissions = (
                claims.get('permissions', []) or
                claims.get('https://scalekit.com/permissions', []) or
                claims.get('scalekit:permissions', []) or
                []
            )
        except Exception as e:
            logger.error(f"Error getting token claims: {e}")
    
    context = {
        'user': user_data,
        'name': user_data.get('name', 'User'),
        'email': user_data.get('email', ''),
        'permissions': permissions,
        'has_organization_settings': 'organization:settings' in permissions,
    }
    
    return render(request, 'auth_app/organization_settings.html', context)
