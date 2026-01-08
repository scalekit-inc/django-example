## Django Scalekit Authentication Example

A simple Django app that shows how to add secure sign-in with Scalekit (OIDC). You can use it as a starting point or as a reference to integrate enterprise-grade authentication.

What this example includes:

- The app signs users in with Scalekit using the OpenID Connect (OIDC) authorization flow.
- The `/dashboard` page is protected and redirects unauthenticated users to the login flow.
- The configuration shows how to register an OAuth 2.0 client and wire login, callback, and logout endpoints.
- The templates use Bootstrap classes so pages render well on desktop and mobile.
- After login, the dashboard displays selected ID token claims to demonstrate how to access user information.

### Prerequisites

- Python 3.8 or later is installed.
- pip is installed.
- You have a Scalekit account with an OIDC application. [Sign up](https://app.scalekit.com/)

## 🛠️ Quick start

### Configure Scalekit

Pick one method below.

_Method A_ — .env file (recommended for local dev):

Create or update `.env` in the project root:

```env
# Replace placeholders with your values
SCALEKIT_ENV_URL=https://your-env.scalekit.io
SCALEKIT_CLIENT_ID=YOUR_CLIENT_ID
SCALEKIT_CLIENT_SECRET=YOUR_CLIENT_SECRET
SCALEKIT_REDIRECT_URI=http://localhost:8000/auth/callback

# Optional server config
DEBUG=True
```

_Method B_ — environment variables:

```bash
export SCALEKIT_ENV_URL=https://your-env.scalekit.io
export SCALEKIT_CLIENT_ID=YOUR_CLIENT_ID
export SCALEKIT_CLIENT_SECRET=YOUR_CLIENT_SECRET
export SCALEKIT_REDIRECT_URI=http://localhost:8000/auth/callback
```

Important:

- Never commit secrets to source control.
- Ensure the redirect URI exactly matches what is configured in Scalekit.

### Build and run

```bash
# Install dependencies
pip install -r requirements.txt

# Run migrations (creates session tables - creates db.sqlite3 file automatically)
python manage.py migrate

# Run the application
python manage.py runserver
```

**Note:** The `db.sqlite3` file is created automatically and stores session data. It's already in `.gitignore` so it won't be committed.

The application will start at `http://localhost:8000`

### Setup Scalekit

To find your required values:

1.  Visit [Scalekit Dashboard](https://app.scalekit.com) and proceed to _Settings_

2.  Copy the API credentials

    - **Environment URL** (e.g., `https://your-env.scalekit.dev`)
    - **Client ID**
    - **Client Secret**

3.  Authentication > Redirect URLs > Allowed redirect URIs:
    - Add `http://localhost:8000/auth/callback` (no trailing slash)
    - Optionally add `http://localhost:8000` as a post-logout redirect

### Application routes

| Route                            | Description                 | Auth required |
| -------------------------------- | --------------------------- | ------------- |
| `/`                              | Home page with login option | No            |
| `/login`                         | Custom login page           | No            |
| `/auth/callback`                 | OIDC callback               | No            |
| `/dashboard`                     | Protected dashboard         | Yes           |
| `/sessions`                      | Session management          | Yes           |
| `/logout`                        | Logout and end session      | Yes           |

### 🚦 Try the app

1. Start the app (see Quick start)
2. Visit `http://localhost:8000`
3. Click Sign in with Scalekit
4. Authenticate with your provider
5. Open the dashboard and then try logout

Stuck? [Contact us](https://docs.scalekit.com/support/contact-us/).

#### Enable debug logging

Add this to `scalekit_django_auth/settings.py`:

```python
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
        'level': 'DEBUG',
    },
    'loggers': {
        'auth_app': {
            'handlers': ['console'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
}
```

#### Code structure

```
scalekit-django-auth-example/
├── auth_app/                    # Main authentication application
│   ├── __init__.py
│   ├── apps.py
│   ├── models.py                # No database models (session-based)
│   ├── views.py                 # Authentication views
│   ├── urls.py                  # URL routing
│   ├── scalekit_client.py       # Scalekit OAuth client
│   ├── middleware.py            # Token refresh middleware
│   └── decorators.py            # Authentication decorators
├── scalekit_django_auth/        # Django project settings
│   ├── __init__.py
│   ├── settings.py              # Django configuration
│   ├── urls.py                  # Root URL configuration
│   ├── wsgi.py
│   └── asgi.py
├── templates/                   # HTML templates
│   └── auth_app/
│       ├── index.html           # Home page
│       ├── login.html           # Login page
│       ├── dashboard.html       # User dashboard
│       ├── sessions.html        # Session management
│       └── error.html           # Error page
├── manage.py                    # Django management script
├── requirements.txt             # Python dependencies
├── .env.example                # Environment variables template
├── .gitignore
└── README.md                   # This file
```

#### Dependencies

- Django 4.2+
- **scalekit-sdk-python** (Official Scalekit Python SDK)
- python-dotenv (for environment variable management)
- PyJWT (for token validation)
- cryptography (for security)

See `requirements.txt` for exact versions.

#### Scalekit SDK Methods Used

This application uses the official Scalekit Python SDK for all authentication operations:

- `ScalekitClient.get_authorization_url()` - Generate OAuth authorization URL
- `ScalekitClient.authenticate_with_code()` - Exchange code for tokens
- `ScalekitClient.validate_access_token_and_get_claims()` - Validate tokens and extract permissions
- `ScalekitClient.refresh_access_token()` - Refresh expired tokens
- `ScalekitClient.get_logout_url()` - Generate logout URL

The following SDK methods are used:
- `ScalekitClient.get_authorization_url()` - Generate OAuth authorization URL
- `ScalekitClient.authenticate_with_code()` - Exchange code for tokens
- `ScalekitClient.validate_access_token_and_get_claims()` - Validate tokens and extract permissions
- `ScalekitClient.refresh_access_token()` - Refresh expired tokens
- `ScalekitClient.get_logout_url()` - Generate logout URL

#### Support

- Read the Scalekit docs: [Documentation](https://docs.scalekit.com).
- Read the Django docs: [Documentation](https://docs.djangoproject.com).

#### License 📄

This project is for demonstration and learning. Refer to dependency licenses for production use.
