"""
Custom middleware for Scalekit token refresh and session management.
Uses session-based storage (no database).
"""
import logging
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from auth_app.scalekit_client import scalekit_client
from datetime import timedelta
from django.utils import timezone

logger = logging.getLogger(__name__)


class ScalekitTokenRefreshMiddleware(MiddlewareMixin):
    """
    Middleware that automatically refreshes expired Scalekit access tokens.
    Uses session-based storage (no database).
    
    This middleware:
    1. Checks if the user has an active Scalekit session
    2. Validates if the access token is expired or about to expire
    3. Automatically refreshes the token if needed
    4. Updates the session with new token information
    """
    
    
    def process_request(self, request):
        """
        Process each request to check and refresh tokens if needed.
        """
        # Skip token refresh for unauthenticated users
        if not request.session.get('scalekit_user'):
            return None
        
        # Skip token refresh for certain paths
        skip_paths = ['/login', '/auth/callback', '/logout', '/static/', '/sessions/refresh-token']
        if any(request.path.startswith(path) for path in skip_paths):
            return None
        
        try:
            # Get token data from session
            token_data = request.session.get('scalekit_tokens', {})
            if not token_data:
                return None
            
            # Check if token is expired or about to expire
            expires_at_str = token_data.get('expires_at')
            if not expires_at_str:
                return None
            
            try:
                expires_at = timezone.datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))
                if expires_at.tzinfo is None:
                    expires_at = timezone.make_aware(expires_at)
            except Exception as e:
                logger.error(f"Error parsing expires_at: {e}")
                return None
            
            # Check if token is expired or expiring soon (within 1 minute)
            buffer_time = timedelta(minutes=1)
            if timezone.now() + buffer_time >= expires_at:
                # Token is expired or expiring soon, try to refresh it
                refresh_token = token_data.get('refresh_token')
                if refresh_token:
                    try:
                        logger.info("Refreshing token automatically")
                        client = scalekit_client()
                        token_response = client.refresh_access_token(refresh_token)
                        
                        # Update session with new tokens
                        expires_in = token_response.get('expires_in', 3600)
                        new_expires_at = timezone.now() + timedelta(seconds=expires_in)
                        
                        request.session['scalekit_tokens'] = {
                            'access_token': token_response.get('access_token'),
                            'refresh_token': token_response.get('refresh_token', refresh_token),
                            'id_token': token_response.get('id_token', token_data.get('id_token')),
                            'expires_at': new_expires_at.isoformat(),
                            'expires_in': expires_in,
                        }
                        
                        logger.info("Token refreshed successfully")
                    except Exception as e:
                        logger.error(f"Failed to refresh token: {e}")
                        # If refresh fails, user will need to re-authenticate
                else:
                    logger.warning("No refresh token available")
        
        except Exception as e:
            logger.error(f"Error in token refresh middleware: {e}")
        
        return None
