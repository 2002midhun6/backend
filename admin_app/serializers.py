from account.models import CustomUser,ProfessionalProfile
from rest_framework import serializers
from account.serializers import UserSerializer
import logging
import urllib.parse
logger = logging.getLogger(__name__) 
class UserBlockSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['is_blocked']
class AdminVerificationSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    verify_doc_url = serializers.SerializerMethodField()
    verify_doc_filename = serializers.SerializerMethodField()
    
    class Meta:
        model = ProfessionalProfile
        fields = [
            'bio',
            'skills',
            'experience_years',
            'availability_status',
            'portfolio_links',
            'verify_status',
            'avg_rating',
            'user',
            'verify_doc',
            'verify_doc_url',
            'verify_doc_filename',
            'denial_reason',
        ]
        read_only_fields = ['verify_doc_url', 'verify_doc_filename']

    def get_verify_doc_url(self, obj):
        """Return the full URL of the verification document if it exists"""
        try:
            if hasattr(obj, 'verify_doc') and obj.verify_doc:
                return obj.verify_doc.url
            return None
        except Exception as e:
            logger.error(f"Error getting document URL for user {obj.user.id}: {e}")
            return None

    def get_verify_doc_filename(self, obj):
        """Extract filename from Cloudinary URL"""
        try:
            if hasattr(obj, 'verify_doc') and obj.verify_doc:
                # Get the URL
                url = obj.verify_doc.url
                if url:
                    # Extract filename from Cloudinary URL
                    if 'cloudinary.com' in url:
                        # Cloudinary URLs typically end with the filename
                        parts = url.split('/')
                        # Get the last part which should be the filename
                        filename_with_extension = parts[-1]
                        # Remove any query parameters
                        filename = filename_with_extension.split('?')[0]
                        # Decode URL encoding
                        decoded_filename = urllib.parse.unquote(filename)
                        return decoded_filename if decoded_filename else 'verification_document'
                    else:
                        # Fallback for other URLs
                        return url.split('/')[-1].split('?')[0]
            return 'verification_document'
        except Exception as e:
            logger.error(f"Error extracting filename for user {obj.user.id}: {e}")
            return 'verification_document'