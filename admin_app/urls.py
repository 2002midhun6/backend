
from django.contrib import admin
from django.urls import path,include
from django.conf import settings
from django.conf.urls.static import static
from account.views import health_check
import os
from .views import AdminVerifyProfessionalView,AdminVerificationRequestsView,BlockUnblockUserView,AdminJobsView,ListUsersView,UserCountsView,JobCountsView

urlpatterns = [
path('admin/verify-professional/<int:professional_id>/', AdminVerifyProfessionalView.as_view(), name='admin_verify_professional'),
path('admin/verification-requests/', AdminVerificationRequestsView.as_view(), name='admin_verification_requests'),
path('users/<int:user_id>/block-unblock/', BlockUnblockUserView.as_view(), name='block-unblock-user'),
path('admin/jobs/', AdminJobsView.as_view(), name='admin-jobs'),
path('users/', ListUsersView.as_view(), name='list-users'),
path('users/counts/', UserCountsView.as_view(), name='user-counts'),
    path('jobs/counts/', JobCountsView.as_view(), name='job-counts'),
 
]