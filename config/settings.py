from pathlib import Path

import environ
from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent
env = environ.Env()
environ.Env.read_env(BASE_DIR / '.env')

try:
    SECRET_KEY = env('DJANGO_SECRET_KEY')
except Exception as exc:
    raise ImproperlyConfigured(
        'Missing required environment variable DJANGO_SECRET_KEY. '
        'Set it in your environment or .env file before starting Django.'
    ) from exc

DEBUG = env.bool('DJANGO_DEBUG', default=True)
ALLOWED_HOSTS = env.list('DJANGO_ALLOWED_HOSTS', default=[])
CSRF_TRUSTED_ORIGINS = env.list('DJANGO_CSRF_TRUSTED_ORIGINS', default=[])


INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'django_filters',
    'accounts.apps.AccountsConfig',
    'pki',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'config.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'config.wsgi.application'

DATABASES = {
    'default': env.db('DJANGO_DB_URL', default=f'sqlite:///{BASE_DIR / "db.sqlite3"}'),
}

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

LANGUAGE_CODE = env('DJANGO_LANGUAGE_CODE', default='en-us')
TIME_ZONE = env('DJANGO_TIME_ZONE', default='UTC')
USE_I18N = env.bool('DJANGO_USE_I18N', default=True)
USE_TZ = env.bool('DJANGO_USE_TZ', default=True)

STATIC_URL = env('DJANGO_STATIC_URL', default='static/')

AUTH_USER_MODEL = 'accounts.User'

LOGIN_URL = env('DJANGO_LOGIN_URL', default='login')
LOGIN_REDIRECT_URL = env('DJANGO_LOGIN_REDIRECT_URL', default='profile')
LOGOUT_REDIRECT_URL = env('DJANGO_LOGOUT_REDIRECT_URL', default='login')

DEFAULT_AUTO_FIELD = env('DJANGO_DEFAULT_AUTO_FIELD', default='django.db.models.BigAutoField')

REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.BasicAuthentication',
    ],
    'DEFAULT_SCHEMA_CLASS': 'rest_framework.schemas.openapi.AutoSchema',
}
