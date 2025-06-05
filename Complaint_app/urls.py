
from django.contrib import admin
from django.urls import path,include
from django.conf import settings
from django.conf.urls.static import static
from account.views import health_check
import os
from .views import ComplaintListCreateView,ComplaintDetailView,ComplaintFeedbackView,AdminComplaintListView,AdminComplaintResponseView

urlpatterns = [
   path('complaints/', ComplaintListCreateView.as_view(), name='complaint-list-create'),
    path('complaints/<int:pk>/', ComplaintDetailView.as_view(), name='complaint-detail'),
    path('complaints/<int:pk>/feedback/', ComplaintFeedbackView.as_view(), name='complaint-feedback'),  
    path('admin/complaints/', AdminComplaintListView.as_view(), name='admin-complaint-list'),
    path('admin/complaints/<int:pk>/respond/', AdminComplaintResponseView.as_view(), name='admin-complaint-response'),  

]
