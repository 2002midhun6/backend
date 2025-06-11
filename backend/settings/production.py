from .base import *

DEBUG = False

ALLOWED_HOSTS = [
    'jobseeker-69742084525.us-central1.run.app',
    '*.run.app',
    'midhung.in',
    'www.midhung.in',
    '13.60.53.135',
    'api.midhung.in',
]

CORS_ALLOWED_ORIGINS = [
    'https://midhung.in',
    'https://www.midhung.in',
    'https://jobseeker-69742084525.us-central1.run.app',
]

CSRF_TRUSTED_ORIGINS = [
    'https://midhung.in',
    'https://www.midhung.in',
    'https://jobseeker-69742084525.us-central1.run.app',
]

SIMPLE_JWT.update({
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=1),
    'SLIDING_TOKEN_LIFETIME': timedelta(minutes=60),
})