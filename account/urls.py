from django.urls import path
from .views import RegisterView, LoginView, LogoutView, VerifyOTPView, ForgotPasswordView, ResetPasswordView, AcceptJobApplicationView, JobDetailView, RequestVerificationView, ProfessionalJobApplicationsView, SubmitReviewView,  ConversationView, UnreadMessagesCountView, CreateMissingConversationsView, FileUploadView,FileRecoveryView
from .views import CheckAuthView,  ProfessionalProfileView, JobCreateView, OpenJobsListView, ApplyToJobView, ClientProjectsView, JobApplicationsListView,  VerifyPaymentView, ClientPendingPaymentsView, ClientTransactionHistoryView,  ProfessionalTransactionHistoryView, UserConversationsView, CheckJobStatesView, WebSocketAuthTokenView
from .views import PaymentTotalView,ResendOTPView,TokenRefreshView,ClientProfileView
from account.views import (
    NotificationListView,
    NotificationCountView,
    MarkNotificationReadView,
    MarkAllNotificationsReadView
    
)
    
urlpatterns = [
   
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify-otp'),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot-password'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),
    path('check-auth/', CheckAuthView.as_view(), name='check-auth'),
    path('profile/', ProfessionalProfileView.as_view(), name='professional-profile'),
    path('jobs/', JobCreateView.as_view(), name='job-create'),
    path('open-jobs/', OpenJobsListView.as_view(), name='open-jobs-list'),
    path('apply-to-job/', ApplyToJobView.as_view(), name='apply_to_job'),
    path('client-project/', ClientProjectsView.as_view(), name='client_projects'),
    path('job-applications/<int:job_id>/', JobApplicationsListView.as_view(), name='job_applications'),
    path('accept-application/<int:application_id>/', AcceptJobApplicationView.as_view(), name='accept_application'),
    path('jobs/<int:job_id>/', JobDetailView.as_view(), name='job_detail'),
    path('request-verification/', RequestVerificationView.as_view(), name='request_verification'),
    path('professional-job-applications/', ProfessionalJobApplicationsView.as_view(), name='professional-job-applications'),
    path('verify-payment/', VerifyPaymentView.as_view(), name='verify-payment'),
    path('client-pending-payments/', ClientPendingPaymentsView.as_view(), name='client_pending_payments'),
    path('submit-review/', SubmitReviewView.as_view(), name='submit-review'),
    path('client/transactions/', ClientTransactionHistoryView.as_view(), name='client-transactions'),
    path('professional/transactions/', ProfessionalTransactionHistoryView.as_view(), name='professional-transactions'),
    path('conversations/', UserConversationsView.as_view(), name='user_conversations'),
    path('conversations/job/<int:job_id>/', ConversationView.as_view(), name='conversation'),
    path('conversations/unread-count/', UnreadMessagesCountView.as_view(), name='unread_messages_count'),
    path('create-missing-conversations/', CreateMissingConversationsView.as_view(), name='create_missing_conversations'),
    path('check-job-states/', CheckJobStatesView.as_view(), name='check_job_states'),
    path('ws-auth-token/', WebSocketAuthTokenView.as_view(), name='ws-auth-token'),
    path('conversations/job/<int:job_id>/file/', FileUploadView.as_view(), name='file-upload'),
    path('conversations/file-recovery/', FileRecoveryView.as_view(), name='file-recovery'),
    path('payments/total/', PaymentTotalView.as_view(), name='payment-total'),
    path('resend-otp/', ResendOTPView.as_view(), name='resend-otp'),
    path('notifications/', NotificationListView.as_view(), name='notification-list'),
    path('notifications/count/', NotificationCountView.as_view(), name='notification-count'),
    path('notifications/mark-read/', MarkNotificationReadView.as_view(), name='mark-notification-read'),
    path('notifications/mark-all-read/', MarkAllNotificationsReadView.as_view(), name='mark-all-notifications-read'),
     path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'), 
      path('client/profile/', ClientProfileView.as_view(), name='client-profile'),
]