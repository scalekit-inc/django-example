"""
Scalekit OAuth 2.0 / OIDC client implementation using official Scalekit SDK.
Handles authentication flows, token management, and user info retrieval.
"""
import logging
from datetime import timedelta
from django.conf import settings
from django.utils import timezone
from scalekit import ScalekitClient as SDKClient
from scalekit.common.scalekit import (
    AuthorizationUrlOptions,
    CodeAuthenticationOptions,
    TokenValidationOptions,
)

logger = logging.getLogger(__name__)


class ScalekitClient:
    """
    Client for interacting with Scalekit OAuth 2.0 / OIDC endpoints.
    
    This class handles:
    - Authorization URL generation
    - Token exchange
    - Token refresh
    - User info retrieval
    - Token validation
    """

    def __init__(self):
        """
        Initialize Scalekit client using official SDK.
        """
        self.domain = settings.SCALEKIT_ENV_URL
        self.client_id = settings.SCALEKIT_CLIENT_ID
        self.client_secret = settings.SCALEKIT_CLIENT_SECRET
        self.redirect_uri = settings.SCALEKIT_REDIRECT_URI
        self.scopes = settings.SCALEKIT_SCOPES.split() if settings.SCALEKIT_SCOPES else ['openid', 'profile', 'email', 'offline_access']
        
        # Validate required settings before initializing SDK
        if not self.domain:
            raise ValueError(
                "SCALEKIT_ENV_URL or SCALEKIT_ENVIRONMENT_URL is not set. Please set it in your .env file or environment variables.\n"
                "Example: SCALEKIT_ENV_URL=https://your-env.scalekit.io\n"
                "Or: SCALEKIT_ENVIRONMENT_URL=https://your-env.scalekit.io\n"
                "See .env.example for a template."
            )
        if not self.client_id:
            raise ValueError(
                "SCALEKIT_CLIENT_ID is not set. Please set it in your .env file or environment variables.\n"
                "Get your client ID from https://app.scalekit.com\n"
                "See .env.example for a template."
            )
        if not self.client_secret:
            raise ValueError(
                "SCALEKIT_CLIENT_SECRET is not set. Please set it in your .env file or environment variables.\n"
                "Get your client secret from https://app.scalekit.com\n"
                "See .env.example for a template."
            )
        if not self.redirect_uri:
            raise ValueError(
                "SCALEKIT_REDIRECT_URI is not set. Please set it in your .env file or environment variables.\n"
                "Example: SCALEKIT_REDIRECT_URI=http://localhost:8000/auth/callback\n"
                "See .env.example for a template."
            )
        
        # Initialize official Scalekit SDK client
        self.sdk_client = SDKClient(
            env_url=self.domain,
            client_id=self.client_id,
            client_secret=self.client_secret
        )

    def get_authorization_url(self, state=None):
        """
        Generate the authorization URL for OAuth 2.0 login flow using Scalekit SDK.
        
        SDK Method Used: ScalekitClient.get_authorization_url()
        
        Args:
            state: Optional state parameter for CSRF protection
            
        Returns:
            str: Authorization URL to redirect user to
        """
        options = AuthorizationUrlOptions()
        options.state = state
        options.scopes = self.scopes
        
        # Use official SDK method
        auth_url = self.sdk_client.get_authorization_url(
            redirect_uri=self.redirect_uri,
            options=options
        )
        
        return auth_url

    def exchange_code_for_tokens(self, code):
        """
        Exchange authorization code for access and refresh tokens using Scalekit SDK.
        
        SDK Method Used: ScalekitClient.authenticate_with_code()
        
        Args:
            code: Authorization code from OAuth callback
            
        Returns:
            dict: Token response containing access_token, refresh_token, expires_in, etc.
            
        Raises:
            Exception: If token exchange fails
        """
        try:
            options = CodeAuthenticationOptions()
            
            # Use official SDK method (returns dict)
            token_response = self.sdk_client.authenticate_with_code(
                code=code,
                redirect_uri=self.redirect_uri,
                options=options
            )
            
            # SDK returns dict with access_token, refresh_token, id_token, etc.
            # Ensure we have expires_in (default to 3600 if not present)
            if 'expires_in' not in token_response:
                token_response['expires_in'] = 3600
            
            return token_response
                
        except Exception as e:
            logger.error(f"Token exchange failed: {e}")
            raise Exception(f"Failed to exchange code for tokens: {str(e)}")

    def refresh_access_token(self, refresh_token):
        """
        Refresh an expired access token using the refresh token via Scalekit SDK.
        
        SDK Method Used: ScalekitClient.refresh_access_token()
        
        Args:
            refresh_token: The refresh token from previous authentication
            
        Returns:
            dict: New token response containing updated access_token, etc.
            
        Raises:
            Exception: If token refresh fails
        """
        try:
            # Use official SDK method (returns dict with access_token and refresh_token)
            token_response = self.sdk_client.refresh_access_token(refresh_token)
            
            # SDK returns dict with access_token and refresh_token
            # Ensure we have expires_in (default to 3600 if not present)
            if 'expires_in' not in token_response:
                token_response['expires_in'] = 3600
            
            # Preserve old refresh_token if new one not provided
            if 'refresh_token' not in token_response or not token_response['refresh_token']:
                token_response['refresh_token'] = refresh_token
            
            return token_response
                
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            raise Exception(f"Failed to refresh access token: {str(e)}")

    def get_user_info(self, access_token):
        """
        Retrieve user information from access token claims using Scalekit SDK.
        
        SDK Method Used: ScalekitClient.validate_access_token_and_get_claims()
        
        Args:
            access_token: Valid OAuth 2.0 access token
            
        Returns:
            dict: User information including email, name, roles, permissions, etc.
            
        Raises:
            Exception: If user info retrieval fails
        """
        try:
            # Use SDK to validate token and get claims (which includes user info)
            validation_options = TokenValidationOptions()
            claims = self.sdk_client.validate_access_token_and_get_claims(
                token=access_token,
                options=validation_options
            )
            
            # Claims contain user information
            return claims
            
        except Exception as e:
            logger.error(f"User info retrieval failed: {e}")
            raise Exception(f"Failed to retrieve user info: {str(e)}")

    def is_token_expired(self, expires_at):
        """
        Check if a token has expired.
        
        Args:
            expires_at: DateTime when the token expires
            
        Returns:
            bool: True if token is expired or expires within 5 minutes
        """
        if not expires_at:
            return True
        
        # Consider token expired if it expires within 5 minutes
        buffer_time = timedelta(minutes=5)
        return timezone.now() + buffer_time >= expires_at

    def logout(self, access_token, id_token=None):
        """
        Get logout URL using Scalekit SDK.
        
        SDK Method Used: ScalekitClient.get_logout_url()
        
        Args:
            access_token: Current access token (not used in SDK, but kept for compatibility)
            id_token: ID token to send as id_token_hint for proper OIDC logout
            
        Returns:
            str: Logout URL (caller should redirect user to this URL)
        """
        from scalekit.common.scalekit import LogoutUrlOptions
        
        options = LogoutUrlOptions()
        options.post_logout_redirect_uri = settings.SCALEKIT_REDIRECT_URI.replace('/auth/callback', '')
        
        # Set id_token_hint if ID token is provided
        if id_token:
            options.id_token_hint = id_token
        
        # Use official SDK method to get logout URL
        logout_url = self.sdk_client.get_logout_url(options)
        return logout_url

    def validate_token_and_get_claims(self, access_token):
        """
        Validate access token using Scalekit SDK and get claims including permissions.
        
        SDK Method Used: ScalekitClient.validate_access_token_and_get_claims()
        
        Args:
            access_token: OAuth 2.0 access token to validate
            
        Returns:
            dict: Token claims including permissions, roles, etc.
            
        Raises:
            Exception: If token validation fails
        """
        try:
            # Use official SDK method for token validation
            validation_options = TokenValidationOptions()
            claims = self.sdk_client.validate_access_token_and_get_claims(
                token=access_token,
                options=validation_options
            )
            
            logger.debug(f"Token validated using Scalekit SDK. Claims keys: {list(claims.keys()) if claims else 'None'}")
            return claims
                
        except Exception as e:
            logger.error(f"Token validation failed: {e}")
            raise Exception(f"Failed to validate token: {str(e)}")
    
    def has_permission(self, access_token, permission):
        """
        Check if the access token has a specific permission.
        
        Args:
            access_token: OAuth 2.0 access token
            permission: Permission name to check (e.g., 'organization:settings')
            
        Returns:
            bool: True if user has the permission
        """
        try:
            claims = self.validate_token_and_get_claims(access_token)
            
            # Check permissions in various possible claim locations
            permissions = (
                claims.get('permissions', []) or
                claims.get('https://scalekit.com/permissions', []) or
                claims.get('scalekit:permissions', []) or
                []
            )
            
            # Also check in scope if permissions not found
            if not permissions:
                scope = claims.get('scope', '')
                if isinstance(scope, str):
                    permissions = scope.split()
            
            has_permission = permission in permissions
            logger.debug(f"Permission check: {permission} = {has_permission} (found permissions: {permissions})")
            
            return has_permission
            
        except Exception as e:
            logger.error(f"Error checking permission: {e}")
            return False


# Module-level singleton instance for reuse throughout the application
# Since ScalekitClient is stateless (configuration-based), a single instance
# can be safely shared across all requests and views.
_client_instance = None


def scalekit_client():
    """
    Get the shared ScalekitClient instance.
    Creates it on first access (lazy initialization).
    
    Returns:
        ScalekitClient: The shared client instance
    """
    global _client_instance
    if _client_instance is None:
        _client_instance = ScalekitClient()
    return _client_instance

