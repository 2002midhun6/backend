from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework import exceptions
import logging

logger = logging.getLogger(__name__)
class CustomJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        raw_token = request.COOKIES.get('access_token')
        if not raw_token:
            auth_header = request.META.get('HTTP_AUTHORIZATION')
            if auth_header and auth_header.startswith('Bearer '):
                raw_token = auth_header.split(' ')[1]
            else:
                return None  # Don't raise exception, return None
        
        try:
            validated_token = self.get_validated_token(raw_token)
            user = self.get_user(validated_token)
            return (user, validated_token)
        except Exception:
            return None  # Don't raise exception, return None