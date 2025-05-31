# storage.py (create this file in your account app or backend folder)
from django.core.files.storage import FileSystemStorage
from django.conf import settings
import os

class LocalFileStorage(FileSystemStorage):
    """
    Custom storage for conversation files that stores files locally
    instead of using Cloudinary
    """
    def __init__(self, location=None, base_url=None):
        if location is None:
            location = os.path.join(settings.MEDIA_ROOT, 'message')
        if base_url is None:
            base_url = '/media/message/'
        
        # Ensure the directory exists
        os.makedirs(location, exist_ok=True)
        
        super().__init__(location=location, base_url=base_url)
    
    def url(self, name):
        """Return the URL where the file can be retrieved."""
        if name is None:
            return name
        
        # Ensure the URL starts with our base URL
        url = super().url(name)
        if not url.startswith('/media/message/'):
            # If the file path doesn't include the full structure, construct it properly
            return f'/media/message/{name}'
        return url