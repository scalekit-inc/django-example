"""
Django settings for scalekit_django_auth project.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
# For this sample app, a default is provided for local development.
# In production, always set DJANGO_SECRET_KEY in environment variables.
SECRET_KEY = os.getenv('DJANGO_SECRET_KEY', 'django-insecure-change-me-in-production')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.getenv('DEBUG', 'True') == 'True'

ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')

# Application definition
INSTALLED_APPS = [
    'django.contrib.contenttypes',  # Required by sessions
    'django.contrib.sessions',  # Needed for session-based storage
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'auth_app',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'auth_app.middleware.ScalekitTokenRefreshMiddleware',  # Custom middleware for token refresh
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'scalekit_django_auth.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'scalekit_django_auth.wsgi.application'

# Database - Using file-based SQLite for sessions (no setup required, just creates db.sqlite3)
# This is still zero-config - Django creates the file automatically
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# Password validation - Not needed for OAuth-only authentication
AUTH_PASSWORD_VALIDATORS = []

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = 'static/'
# No static files directory needed - using Bootstrap CDN

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Session configuration
SESSION_ENGINE = 'django.contrib.sessions.backends.db'
SESSION_COOKIE_AGE = 3600  # 1 hour
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = False  # Set to False for local development (HTTP)
SESSION_COOKIE_SAMESITE = 'Lax'
SESSION_SAVE_EVERY_REQUEST = True  # Save session on every request to ensure state persistence

# Scalekit Configuration
SCALEKIT_ENV_URL = os.getenv('SCALEKIT_ENV_URL', os.getenv('SCALEKIT_DOMAIN', ''))
SCALEKIT_CLIENT_ID = os.getenv('SCALEKIT_CLIENT_ID', '')
SCALEKIT_CLIENT_SECRET = os.getenv('SCALEKIT_CLIENT_SECRET', '')
SCALEKIT_REDIRECT_URI = os.getenv('SCALEKIT_REDIRECT_URI', 'http://localhost:8000/auth/callback')

# OAuth 2.0 Scopes
# Note: 'offline_access' is needed to get a refresh token
SCALEKIT_SCOPES = 'openid profile email offline_access'

# Login URL
LOGIN_URL = '/login'

# Logging configuration (for debugging OAuth flow)
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'auth_app': {
            'handlers': ['console'],
            'level': 'DEBUG' if DEBUG else 'INFO',
            'propagate': False,
        },
    },
}

