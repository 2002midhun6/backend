"""
URL configuration for backend project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.contrib import admin
from django.urls import path,include
from django.conf import settings
from django.conf.urls.static import static
from account.views import health_check
import os

urlpatterns = [
    path("admin/", admin.site.urls),
    path('api/', include('account.urls')),
    path('api/', include('Complaint_app.urls')),
     path('api/', include('admin_app.urls')),
   path('health/', health_check, name='health_check'),
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    
    # CRITICAL: Add specific handling for message files
    from django.views.static import serve
    from django.urls import re_path
    
    # Serve message files specifically
    urlpatterns += [
        re_path(r'^media/message/(?P<path>.*)$', serve, {
            'document_root': os.path.join(settings.BASE_DIR, 'media', 'message'),
        }),
    ]
else:
    # In production, you might want to serve these through your web server (nginx/apache)
    # or implement a custom view that checks permissions before serving
    pass