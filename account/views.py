from django.shortcuts import render
from django.conf import settings
from rest_framework import status
from rest_framework.response import Response
from rest_framework import generics, permissions
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import UserRegistrationSerializer, UserLoginSerializer, ForgotPasswordSerializer, ResetPasswordSerializer,ProfessionalProfileSerializer
from .models import CustomUser,ProfessionalProfile,Job,JobApplication
from .models import PaymentRequest, Payment
from backend.utils import send_otp_email
from .serializers import OTPVerificationSerializer
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.tokens import AccessToken
import hashlib
import hmac
from decimal import Decimal
from datetime import datetime, timedelta
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
import jwt
from django.db.models import Sum
from django.conf import settings
import logging
from rest_framework.permissions import IsAuthenticated
from rest_framework.permissions import AllowAny
from .serializers import UserBlockSerializer,UserSerializer,JobSerializer,JobApplicationSerializer
from django.core.mail import send_mail
from django.db.models import Q
from django.shortcuts import get_object_or_404
import razorpay


from .serializers import PaymentSerializer
import traceback
from .models import Complaint
from rest_framework import status, generics
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from django.shortcuts import get_object_or_404
from .models import Complaint
from .serializers import ComplaintSerializer
from django.db.models import Q
from .models import Conversation, Message
from .serializers import ConversationSerializer, MessageSerializer
# Add this to account/views.py
from django.contrib.auth import get_user_model
from django.utils import timezone
# accounts/views.py - Update your ApplyToJobView
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from .models import Notification
from .serializers import NotificationSerializer
# accounts/views.py
from rest_framework_simplejwt.tokens import RefreshToken
from django.http import JsonResponse
from rest_framework.decorators import api_view, permission_classes
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
@require_http_methods(["GET"])
def health_check(request):
    return JsonResponse({'status': 'healthy', 'service': 'backend'})
import logging
logger = logging.getLogger(__name__)  # Add this line at the top

class TokenRefreshView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        try:
            refresh_token = request.COOKIES.get('refresh_token')
            logger.debug(f'Refresh token found: {bool(refresh_token)}')
            
            if not refresh_token:
                logger.error('No refresh token found in cookies')
                return Response({'error': 'Refresh token not found'}, status=status.HTTP_401_UNAUTHORIZED)

            try:
                refresh = RefreshToken(refresh_token)
                access_token = str(refresh.access_token)
                
                response_data = {
                    'access': access_token,
                    'success': True
                }
                
                response = Response(response_data, status=status.HTTP_200_OK)
                
                # Set new access token cookie
                response.set_cookie(
                    key='access_token',
                    value=access_token,
                    httponly=True,
                    secure=True,
                    samesite='None',  # Critical for cross-origin
                    max_age=60 * 60,  # 1 hour
                    path='/'
                )
                
                logger.info('Token refreshed successfully')
                return response
                
            except TokenError as e:
                logger.error(f'Invalid refresh token: {str(e)}')
                return Response({'error': 'Invalid or expired refresh token'}, status=status.HTTP_401_UNAUTHORIZED)
                
        except Exception as e:
            logger.error(f'Token refresh error: {str(e)}')
            return Response({'error': 'Token refresh failed'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class NotificationListView(generics.ListAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = NotificationSerializer
    
    def get_queryset(self):
        return Notification.objects.filter(user=self.request.user)

class NotificationCountView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        unread_count = Notification.objects.filter(
            user=request.user,
            is_read=False
        ).count()
        
        return Response({"unread_count": unread_count})

class MarkNotificationReadView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        notification_id = request.data.get('notification_id')
        
        if notification_id:
            try:
                notification = Notification.objects.get(id=notification_id, user=request.user)
                notification.is_read = True
                notification.save()
                return Response({"success": True}, status=status.HTTP_200_OK)
            except Notification.DoesNotExist:
                return Response(
                    {"error": "Notification not found"}, 
                    status=status.HTTP_404_NOT_FOUND
                )
        else:
            return Response(
                {"error": "Notification ID is required"}, 
                status=status.HTTP_400_BAD_REQUEST
            )

class MarkAllNotificationsReadView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        Notification.objects.filter(user=request.user, is_read=False).update(is_read=True)
        return Response({"success": True}, status=status.HTTP_200_OK)
class UserCountsView(APIView):
    permission_classes = [IsAdminUser]
    def get(self, request):
        professional_count = CustomUser.objects.filter(role='professional').count()
        client_count = CustomUser.objects.filter(role='client').count()
        pending_complaints = Complaint.objects.filter(status='Pending').count()
        verified_professionals = CustomUser.objects.filter(
            role='professional', 
            professionalprofile__verify_status='Verified'
        ).count()
        return Response({
            'professionals': professional_count,
            'clients': client_count,
            'pending_complaints': pending_complaints,
            'verified_professionals': verified_professionals
        }, status=status.HTTP_200_OK)

class JobCountsView(APIView):
    permission_classes = [IsAdminUser]
    def get(self, request):
        total_jobs = Job.objects.count()
        completed_jobs = Job.objects.filter(status='Completed').count()
        active_applications = JobApplication.objects.filter(
            status__in=['Pending', 'Accepted']
        ).count()
        # Active conversations: Conversations with messages in the last 30 days
        recent_threshold = datetime.now() - timedelta(days=30)
        active_conversations = Conversation.objects.filter(
            messages__created_at__gte=recent_threshold
        ).distinct().count()
        return Response({
            'total_jobs': total_jobs,
            'completed_jobs': completed_jobs,
            'active_applications': active_applications,
            'active_conversations': active_conversations
        }, status=status.HTTP_200_OK)

class PaymentTotalView(APIView):
    permission_classes = [IsAdminUser]
    def get(self, request):
        total_payments = Payment.objects.aggregate(total=Sum('amount'))['total'] or 0
        return Response({
            'total_payments': total_payments
        }, status=status.HTTP_200_OK)
logger = logging.getLogger('django')
CustomUser = get_user_model()
class WebSocketAuthTokenView(APIView):
    def get(self, request, *args, **kwargs):
        try:
            # Ensure user is authenticated
            if not request.user or request.user.is_anonymous:
                logger.error("Unauthenticated user attempted to access WebSocket token")
                return Response(
                    {"error": "Authentication required"},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            # Generate access token
            access_token = AccessToken.for_user(request.user)
            token_str = str(access_token)
            logger.info(f"Generated WebSocket token for user {request.user.id}")

            return Response(
                {
                    "access_token": token_str,
                    "user_id": request.user.id,  # Fixed: single user_id key, proper comma
                    "email": request.user.email
                },
                status=status.HTTP_200_OK
            )
        except Exception as e:
            logger.error(f"Error generating WebSocket token: {str(e)}")
            return Response(
                {"error": f"Failed to generate token: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class FileUploadView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, job_id):
        try:
            # Add logging to debug request
            logger.info(f"FileUploadView accessed: job_id={job_id}, user={request.user.email}")
            logger.info(f"Request FILES: {request.FILES}")
            
            file = request.FILES.get('file')
            if not file:
                logger.error("No file provided in request")
                return Response({'error': 'No file provided'}, status=status.HTTP_400_BAD_REQUEST)

            max_size = 5 * 1024 * 1024  # 5MB
            if file.size > max_size:
                logger.error(f"File size exceeds limit: {file.size} bytes")
                return Response({'error': 'File size exceeds 5MB limit'}, status=status.HTTP_400_BAD_REQUEST)

            allowed_types = {
                'image': ['image/jpeg', 'image/png', 'image/gif'],
                'document': ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']
            }
            
            logger.info(f"File content type: {file.content_type}")
            file_type = None
            if file.content_type in allowed_types['image']:
                file_type = 'image'
            elif file.content_type in allowed_types['document']:
                file_type = 'document'
            else:
                logger.error(f"Unsupported file type: {file.content_type}")
                return Response({'error': 'Unsupported file type'}, status=status.HTTP_400_BAD_REQUEST)

            try:
                job = Job.objects.get(job_id=job_id)
                conversation, created = Conversation.objects.get_or_create(job=job)
                logger.info(f"Found job and conversation: job_id={job_id}, conversation_id={conversation.id}")
            except Job.DoesNotExist:
                logger.error(f"Job not found: job_id={job_id}")
                return Response({'error': 'Job not found'}, status=status.HTTP_404_NOT_FOUND)

            if request.user != job.client_id:
                application = JobApplication.objects.filter(
                    job_id=job,
                    professional_id=request.user,
                    status='Accepted'
                ).first()
                if not application:
                    logger.error(f"Unauthorized file upload: user={request.user.email}, job_id={job_id}")
                    return Response(
                        {'error': 'You are not authorized to send files in this conversation'},
                        status=status.HTTP_403_FORBIDDEN
                    )

            # Create the message with the file
            message = Message.objects.create(
                conversation=conversation,
                sender=request.user,
                file=file,
                file_type=file_type,
                content=''
            )
            logger.info(f"Created message with file: message_id={message.id}, file_type={file_type}")
            if message.file:
                message.file_absolute_url = request.build_absolute_uri(message.file.url)
                message.save(update_fields=['file_absolute_url'])
            # Send a WebSocket notification
            from channels.layers import get_channel_layer
            from asgiref.sync import async_to_sync
            channel_layer = get_channel_layer()
            room_group_name = f'chat_{job_id}'
            
            # Prepare message data for WebSocket
            message_data = {
                'id': message.id,
                'sender': message.sender.id,
                'sender_name': message.sender.name,
                'sender_role': message.sender.role,
                'content': message.content,
                'file_url': message.file_absolute_url or (request.build_absolute_uri(message.file.url) if message.file else None),
                'file_type': message.file_type,
                'created_at': message.created_at.isoformat(),
                'is_read': False
            }
            
            async_to_sync(channel_layer.group_send)(
                room_group_name,
                {
                    'type': 'chat_message',
                    'message': message_data
                }
            )
            
            serializer = MessageSerializer(message, context={'request': request})
            return Response(serializer.data, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            logger.error(f"File upload error: {str(e)}")
            return Response({'error': f"Failed to upload file: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
class FileRecoveryView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        message_id = request.data.get('message_id')
        
        try:
            message = Message.objects.get(id=message_id)
            
            # Check permissions
            conversation = message.conversation
            job = conversation.job
            if not (request.user == job.client_id or JobApplication.objects.filter(
                job_id=job, professional_id=request.user, status='Accepted'
            ).exists()):
                return Response({'error': 'Not authorized'}, status=403)
            
            # If the file exists but URL is missing
            if message.file and not message.file_absolute_url:
                file_url = request.build_absolute_uri(message.file.url)
                message.file_absolute_url = file_url
                message.save(update_fields=['file_absolute_url'])
                return Response({'success': True, 'new_url': file_url})
                
            # If file exists and URL is present
            elif message.file and message.file_absolute_url:
                return Response({'success': True, 'new_url': message.file_absolute_url})
                
            # File is missing
            else:
                return Response({'error': 'File not found'}, status=404)
                
        except Message.DoesNotExist:
            return Response({'error': 'Message not found'}, status=404)
class CreateMissingConversationsView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        assigned_jobs = Job.objects.filter(status='Assigned')
        created_count = 0
        
        for job in assigned_jobs:
            conversation, created = Conversation.objects.get_or_create(job=job)
            if created:
                created_count += 1
        
        return Response({
            'message': f'Created {created_count} new conversations for assigned jobs',
            'total_assigned_jobs': assigned_jobs.count()
        }, status=status.HTTP_200_OK)

class ConversationView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request, job_id):
        try:
            job = Job.objects.get(job_id=job_id)
            
            if request.user != job.client_id:
                application = JobApplication.objects.filter(
                    job_id=job,
                    professional_id=request.user,
                    status='Accepted'
                ).first()
                
                if not application:
                    return Response(
                        {'error': 'You are not authorized to access this conversation'},
                        status=status.HTTP_403_FORBIDDEN
                    )
            
            conversation, created = Conversation.objects.get_or_create(job=job)
            
            Message.objects.filter(
                conversation=conversation,
                is_read=False
            ).exclude(sender=request.user).update(is_read=True)
            
            serializer = ConversationSerializer(conversation)
            return Response(serializer.data, status=status.HTTP_200_OK)
            serializer = MessageSerializer(messages, many=True, context={'request': request})
            return Response(serializer.data)  
        except Job.DoesNotExist:
            return Response({'error': 'Job not found'}, status=status.HTTP_404_NOT_FOUND)

class UserConversationsView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user = request.user
        
        if user.role == 'client':
            jobs = Job.objects.filter(client_id=user, status='Assigned')
            conversations = Conversation.objects.filter(job__in=jobs)
        else:
            applications = JobApplication.objects.filter(
                professional_id=user,
                status='Accepted'
            )
            jobs = Job.objects.filter(
                job_id__in=applications.values('job_id'),
                status='Assigned'
            )
            conversations = Conversation.objects.filter(job__in=jobs)
        
        debug_info = {
            'user_id': user.id,
            'user_email': user.email,
            'user_role': user.role,
            'assigned_jobs_count': jobs.count(),
            'conversations_count': conversations.count(),
            'job_ids': [job.job_id for job in jobs]
        }
        
        serializer = ConversationSerializer(conversations, many=True)
        
        return Response({
            'conversations': serializer.data,
            'debug_info': debug_info
        }, status=status.HTTP_200_OK)

class UnreadMessagesCountView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user = request.user
        
        if user.role == 'client':
            jobs = Job.objects.filter(client_id=user)
            conversations = Conversation.objects.filter(job__in=jobs)
        else:
           
            jobs = Job.objects.filter(professional_id=user)
            conversations = Conversation.objects.filter(job__in=jobs)
        
        unread_count = Message.objects.filter(
            conversation__in=conversations,
            is_read=False
        ).exclude(sender=user).count()
        
        return Response({'unread_count': unread_count}, status=status.HTTP_200_OK)

class CheckJobStatesView(APIView):
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        user = request.user
        
        if user.role == 'client':
            jobs = Job.objects.filter(client_id=user)
        else:
            applications = JobApplication.objects.filter(professional_id=user)
            jobs = Job.objects.filter(job_id__in=applications.values('job_id'))
        
        job_states = []
        for job in jobs:
            applications = JobApplication.objects.filter(job_id=job)
            job_states.append({
                'job_id': job.job_id,
                'title': job.title,
                'status': job.status,
                'applications': [
                    {
                        'application_id': app.application_id,
                        'professional_id': app.professional_id.id,
                        'professional_email': app.professional_id.email,
                        'status': app.status
                    } for app in applications
                ]
            })
        
        return Response({
            'job_states': job_states,
            'user_role': user.role
        }, status=status.HTTP_200_OK)
class ComplaintListCreateView(generics.ListCreateAPIView):
    """
    View for creating complaints and listing user's own complaints
    """
    serializer_class = ComplaintSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        # Regular users can only see their own complaints
        user = self.request.user
        if user.is_superuser or user.is_staff:
            return Complaint.objects.all().order_by('-created_at')
        return Complaint.objects.filter(user=user).order_by('-created_at')
    
    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class ComplaintDetailView(generics.RetrieveUpdateAPIView):
    """
    View for retrieving and updating a specific complaint
    """
    serializer_class = ComplaintSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        user = self.request.user
        if user.is_superuser or user.is_staff:
            return Complaint.objects.all()
        return Complaint.objects.filter(user=user)
    
    def patch(self, request, *args, **kwargs):
        user = request.user
        complaint = self.get_object()
        
        # Only staff/admin can update status
        if 'status' in request.data and not (user.is_superuser or user.is_staff):
            return Response(
                {'error': 'Only admins can update complaint status'},
                status=status.HTTP_403_FORBIDDEN
            )
            
        return super().patch(request, *args, **kwargs)

class AdminComplaintListView(generics.ListAPIView):
    """
    Admin view for listing all complaints with filtering options
    """
    serializer_class = ComplaintSerializer
    permission_classes = [IsAuthenticated]
    
    def get_permissions(self):
        permissions = super().get_permissions()
        if not self.request.user.is_staff and not self.request.user.is_superuser:
            return [IsAdminUser()]
        return permissions
    
    def get_queryset(self):
        queryset = Complaint.objects.all().order_by('-created_at')
        
        # Filter by status if provided
        status_filter = self.request.query_params.get('status', None)
        if status_filter:
            queryset = queryset.filter(status=status_filter)
            
        # Search by description or user email
        search = self.request.query_params.get('search', None)
        if search:
            queryset = queryset.filter(
                Q(description__icontains=search) | 
                Q(user__email__icontains=search)
            )
            
        return queryset
class ClientPendingPaymentsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            if request.user.role != 'client':
                return Response(
                    {'error': 'Only clients can view pending payments'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
            # Fetch payment requests
            payment_requests = PaymentRequest.objects.filter(client=request.user, status='pending')
            print(f"Payment Requests for {request.user.email}: {payment_requests.count()}")
            print(f"Payment Request IDs: {[pr.request_id for pr in payment_requests]}")
            
            # Get associated payments
            payments = [pr.payment for pr in payment_requests]
            print(f"Payments: {[p.id for p in payments]}")
            
            # Serialize payments
            serializer = PaymentSerializer(payments, many=True, context={'request': request})
            print(f"Serialized Data: {serializer.data}")
            
            return Response({'payments': serializer.data}, status=status.HTTP_200_OK)
        
        except Exception as e:
            print(f"Error in ClientPendingPaymentsView: {str(e)}")
            print(f"Traceback: {traceback.format_exc()}")
            return Response(
                {'error': f'Internal server error: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
class RequestVerificationView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        if request.user.role != 'professional':
            return Response({'error': 'Only professionals can request verification'}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            profile = ProfessionalProfile.objects.get(user=request.user)
            
            # Check if document exists and is accessible
            if not profile.verify_doc:
                return Response({'error': 'Please upload a verification document first'}, status=status.HTTP_400_BAD_REQUEST)
            
            try:
                # Test if the file is accessible
                profile.verify_doc.url
            except Exception as e:
                print(f"File access error: {str(e)}")
                return Response({'error': 'Verification document cannot be accessed. Please re-upload.'}, 
                              status=status.HTTP_400_BAD_REQUEST)
            
            if profile.verify_status == 'Verified':
                return Response({'error': 'Your profile is already verified'}, status=status.HTTP_400_BAD_REQUEST)
            
            # Set status to Pending if it was previously Not Verified
            if profile.verify_status == 'Not Verified':
                profile.verify_status = 'Pending'
                profile.save()
            
            # Email sending code commented out as in your original code
            
            return Response({'message': 'Verification request sent to admin'}, status=status.HTTP_200_OK)
        except ProfessionalProfile.DoesNotExist:
            return Response({'error': 'Profile not found'}, status=status.HTTP_404_NOT_FOUND)
class ClientProjectsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        if user.role != 'client':
            return Response({'error': 'Only clients can view their projects'}, status=status.HTTP_403_FORBIDDEN)

        # Categorize jobs by status
        pending_jobs = Job.objects.filter(client_id=user, status='Open')
        active_jobs = Job.objects.filter(client_id=user, status='Assigned')
        completed_jobs = Job.objects.filter(client_id=user, status='Completed')

        # Serialize each category
        pending_serializer = JobSerializer(pending_jobs, many=True)
        active_serializer = JobSerializer(active_jobs, many=True)
        completed_serializer = JobSerializer(completed_jobs, many=True)

        return Response({
            'pending': pending_serializer.data,
            'active': active_serializer.data,
            'completed': completed_serializer.data
        }, status=status.HTTP_200_OK)
class ListUsersView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        # Fetch all users except superusers
        users = CustomUser.objects.filter(is_superuser=False).order_by('email')
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
class BlockUnblockUserView(APIView):
    permission_classes = [AllowAny]

    def patch(self, request, user_id):
        try:
            user = CustomUser.objects.get(id=user_id)
        except CustomUser.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserBlockSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            action = 'blocked' if user.is_blocked else 'unblocked'
            return Response({'message': f'User has been {action} successfully.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CheckAuthView(APIView):
    permission_classes = [AllowAny]
    
    def get(self, request):
        try:
            access_token = request.COOKIES.get('access_token')
            if not access_token:
                return Response({'isAuthenticated': False})
            
            from rest_framework_simplejwt.tokens import AccessToken
            token = AccessToken(access_token)
            user_id = token.get('user_id')
            
            from django.contrib.auth import get_user_model
            User = get_user_model()
            user = User.objects.get(id=user_id)
            
            return Response({
                'isAuthenticated': True,
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'name': user.name,
                    'role': user.role,
                    'is_staff': user.is_staff
                }
            })
        except:
            return Response({'isAuthenticated': False})
class RegisterView(APIView):
    permission_classes = [AllowAny]  # Optional, depending on your requirements
    authentication_classes = []
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        user = serializer.save()
        send_otp_email(user)  # Send OTP email
        return Response({'message': 'OTP sent to email. Verify your email to activate your account.'}, status=status.HTTP_201_CREATED)
        
        # refresh = RefreshToken.for_user(user)

        # # Set tokens in HTTP-only cookies
        # response = Response({
        #     'user': {
        #         'email': user.email,
        #         'name': user.name,
        #         'role': user.role
        #     }
        # }, status=status.HTTP_201_CREATED)
        # response.set_cookie(
        #     key='access_token',
        #     value=str(refresh.access_token),
        #     httponly=True,
        #     secure=not settings.DEBUG,  # Secure in production
        #     samesite='Lax'
        # )
        # response.set_cookie(
        #     key='refresh_token',
        #     value=str(refresh),
        #     httponly=True,
        #     secure=not settings.DEBUG,
        #     samesite='Lax'
        # )
        # return response

class LoginView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        try:
            logger.info(f'Login attempt for: {request.data.get("email", "no email")}')
            
            serializer = UserLoginSerializer(data=request.data)
            if not serializer.is_valid():
                logger.warning(f'Login validation failed: {serializer.errors}')
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            user = authenticate(
                email=serializer.validated_data['email'], 
                password=serializer.validated_data['password']
            )
            
            if not user:
                logger.warning(f'Failed login attempt for email: {serializer.validated_data["email"]}')
                return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
            
            if user.is_blocked:
                logger.warning(f'Blocked account login attempt: {user.email}')
                return Response({'error': 'Account is blocked'}, status=status.HTTP_401_UNAUTHORIZED)
            
            if not user.is_verified and not user.is_superuser:
                logger.warning(f'Unverified account login attempt: {user.email}')
                return Response({'error': 'Please verify your email before logging in'}, status=status.HTTP_401_UNAUTHORIZED)

            # Generate tokens
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            
            response_data = {
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'name': user.name,
                    'role': user.role,
                    'is_staff': user.is_staff
                },
                'access': access_token,
                'success': True
            }
            
            response = Response(response_data, status=status.HTTP_200_OK)

            # Set cookies with proper settings for cross-origin
            response.set_cookie(
                key='access_token',
                value=access_token,
                httponly=True,
                secure=True,
                samesite='None',  # Critical for cross-origin
                max_age=60 * 60,  # 1 hour
                path='/'
            )
            
            response.set_cookie(
                key='refresh_token',
                value=str(refresh),
                httponly=True,
                secure=True,
                samesite='None',  # Critical for cross-origin
                max_age=60 * 60 * 24 * 7,  # 7 days
                path='/'
            )
            
            logger.info(f'User {user.email} logged in successfully')
            return response
            
        except Exception as e:
            logger.error(f'Login error: {str(e)}')
            return Response({'error': 'Login failed'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LogoutView(APIView):
    permission_classes = [AllowAny]  # Optional, depending on your requirements
    authentication_classes = []
    def post(self, request):
        try:
            refresh_token = request.COOKIES.get('refresh_token')
            if not refresh_token:
                return Response({'error': 'No refresh token provided'}, status=status.HTTP_400_BAD_REQUEST)

            token = RefreshToken(refresh_token)
            token.blacklist()  # Blacklist the token

            response = Response({'message': 'Logged out successfully'}, status=status.HTTP_205_RESET_CONTENT)
            response.delete_cookie('access_token')
            response.delete_cookie('refresh_token')
            return response
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
class VerifyOTPView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    def post(self, request):
        serializer = OTPVerificationSerializer(data=request.data)
        if serializer.is_valid():
            return Response({'message': 'Email verified successfully!'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ResendOTPView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            return Response(
                {'message': 'OTP resent successfully to your email.'},
                status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ForgotPasswordView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            return Response(
                {'message': 'OTP sent to your email for password reset.'},
                status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ResetPasswordView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {'message': 'Password reset successfully! You can now log in.'},
                status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProfessionalProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Fetch the logged-in user's professional profile"""
        user = request.user
        try:
            profile = ProfessionalProfile.objects.get(user=user)
            serializer = ProfessionalProfileSerializer(profile)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except ProfessionalProfile.DoesNotExist:
            return Response({'error': 'Profile not found'}, status=status.HTTP_404_NOT_FOUND)

    def post(self, request):
        """Create a professional profile for the authenticated user"""
        print('POST /api/profile/ - Data:', request.data)
       
        user = request.user
        
        # Check authentication
        if not user.is_authenticated:
            return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)
        
        # Check user role
        if getattr(user, 'role', None) != 'professional':
            return Response({'error': 'Only professionals can create a profile'}, status=status.HTTP_403_FORBIDDEN)
        
        # Prevent duplicate profile creation
        if ProfessionalProfile.objects.filter(user=user).exists():
            return Response({'error': 'Profile already exists'}, status=status.HTTP_400_BAD_REQUEST)

        # Handle file upload
        data = request.data.copy()
        if 'verify_doc' in request.FILES:
            data['verify_doc'] = request.FILES['verify_doc']

        # Deserialize and save the profile
        serializer = ProfessionalProfileSerializer(data=data)
        if serializer.is_valid():
            serializer.save(user=user)
            return Response({'message': 'Profile created successfully'}, status=status.HTTP_201_CREATED)
        
        # Debugging serializer errors
        print('Serializer errors:', serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request):
        print('PATCH /api/profile/ - Data:', request.data)
        print('PATCH /api/profile/ - Files:', request.FILES)  # Add this to debug file uploads
        user = request.user

        if not user.is_authenticated:
            return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)

        if getattr(user, 'role', None) != 'professional':
            return Response({'error': 'Only professionals can update a profile'}, status=status.HTTP_403_FORBIDDEN)

        try:
            profile = ProfessionalProfile.objects.get(user=user)
            
            # Handle file upload
            data = request.data.copy()
            if 'verify_doc' in request.FILES:
                data['verify_doc'] = request.FILES['verify_doc']
            
            serializer = ProfessionalProfileSerializer(profile, data=data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response({'message': 'Profile updated successfully'}, status=status.HTTP_200_OK)
           
            print('Serializer errors:', serializer.errors)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except ProfessionalProfile.DoesNotExist:
            return Response({'error': 'Profile not found. Please create a profile first.'}, status=status.HTTP_404_NOT_FOUND)
class JobCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        if request.user.role != 'client':
            return Response(
                {'error': 'Only clients can post jobs'},
                status=status.HTTP_403_FORBIDDEN
            )

        serializer = JobSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(client_id=request.user)  # Associate job with authenticated user
            return Response(
                serializer.data,
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
class OpenJobsListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Ensure only clients can access this view
        if request.user.role == 'client':
            return Response(
                {'error': 'Only Professional  can view open jobs'},
                status=status.HTTP_403_FORBIDDEN
            )
        
       
        open_jobs = Job.objects.filter(status='Open')
        serializer = JobSerializer(open_jobs, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class ApplyToJobView(generics.CreateAPIView):
    queryset = JobApplication.objects.all()
    serializer_class = JobApplicationSerializer
    permission_classes = [IsAuthenticated]  

    def perform_create(self, serializer):
        # Save the application
        application = serializer.save(professional_id=self.request.user)
        
        # Get job and client details
        job = application.job_id
        client = job.client_id
        
        # Get professional profile data
        try:
            profile = ProfessionalProfile.objects.get(user=self.request.user)
            profile_data = ProfessionalProfileSerializer(profile).data
        except ProfessionalProfile.DoesNotExist:
            profile_data = {}
        
        # Create a database notification
        notification_data = {
            'job_id': job.job_id,
            'job_title': job.title, 
            'professional_id': self.request.user.id,
            'professional_name': self.request.user.name,
            'application_id': application.application_id,
            'profile_data': {
                'experience_years': profile_data.get('experience_years', 0),
                'avg_rating': profile_data.get('avg_rating', 0),
                'verify_status': profile_data.get('verify_status', 'Not Verified'),
                'availability_status': profile_data.get('availability_status', 'Unknown')
            }
        }
        
        try:
            # Create persistent notification
            Notification.objects.create(
                user=client,
                notification_type='job_application',
                title=f'New application for {job.title}',
                message=f'{self.request.user.name} has applied for your job: {job.title}',
                data=notification_data
            )
        except Exception as e:
            print(f"Failed to create notification record: {str(e)}")
        
        # Send real-time notification via WebSocket
        channel_layer = get_channel_layer()
        
        # Prepare notification data
        ws_notification_data = {
            'type': 'job_application',
            'job_id': job.job_id,
            'job_title': job.title,
            'professional_id': self.request.user.id,
            'professional_name': self.request.user.name,
            'professional_email': self.request.user.email,
            'application_id': application.application_id,
            'timestamp': timezone.now().isoformat(),
            'notification_id': str(application.application_id),
            'profile_data': notification_data['profile_data']
        }
        
        # Send notification to client's notification group
        try:
            async_to_sync(channel_layer.group_send)(
                f'notifications_{client.id}',
                {
                    'type': 'send_notification',
                    'content': ws_notification_data
                }
            )
            print(f"Sent WebSocket notification to client {client.id} about new application {application.application_id}")
        except Exception as e:
            print(f"Failed to send WebSocket notification: {str(e)}")

class JobDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, job_id):
        if request.user.role != 'client':
            return Response(
                {'error': 'Only clients can view job details'},
                status=status.HTTP_403_FORBIDDEN
            )

        job = get_object_or_404(Job, job_id=job_id, client_id=request.user)
        serializer = JobSerializer(job)
        return Response(serializer.data)

    def put(self, request, job_id):
        if request.user.role != 'client':
            return Response(
                {'error': 'Only clients can edit jobs'},
                status=status.HTTP_403_FORBIDDEN
            )

        job = get_object_or_404(Job, job_id=job_id, client_id=request.user)
        if job.status != 'Open':
            return Response(
                {'error': 'Only open projects can be edited'},
                status=status.HTTP_400_BAD_REQUEST
            )
        if job.applications.exists():
            return Response(
                {'error': 'Cannot edit jobs with applicants'},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = JobSerializer(job, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {'message': 'Project updated successfully'},
                status=status.HTTP_200_OK
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
class JobApplicationsListView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, job_id):
        try:
            job = Job.objects.get(job_id=job_id)
            if request.user != job.client_id:
                return Response(
                    {'error': 'You are not authorized to view applications for this job'},
                    status=status.HTTP_403_FORBIDDEN
                )
            applications = JobApplication.objects.filter(job_id=job)
            serializer = JobApplicationSerializer(applications, many=True)
            print('Serialized Applications:', serializer.data)  # Debug
            return Response({
                'applications': serializer.data,
                'job_title': job.title
            }, status=status.HTTP_200_OK)
        except Job.DoesNotExist:
            return Response({'error': 'Job not found'}, status=status.HTTP_404_NOT_FOUND)


import razorpay
import traceback
import time
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from .models import JobApplication, Job, Payment
from django.conf import settings

class AcceptJobApplicationView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, application_id):
        try:
            # Get the application and job
            application = JobApplication.objects.get(application_id=application_id)
            job = application.job_id

            # Check if the user is the client who posted the job
            if request.user != job.client_id:
                return Response(
                    {'error': 'You are not authorized to accept this application'},
                    status=status.HTTP_403_FORBIDDEN
                )

            # Check if job is still open
            if job.status != 'Open':
                return Response(
                    {'error': 'This job is not open for assignment'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Check if application is still in 'Applied' status
            if application.status != 'Applied':
                return Response(
                    {'error': 'This application has already been processed'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Initialize Razorpay client
            client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

            # Determine initial payment amount (advance_payment or 50% of budget)
            if job.advance_payment is not None:
                amount = job.advance_payment
            else:
                amount = job.budget * 0.5  # Default to 50% of budget
            amount_in_paisa = int(amount * 100)  # Convert to paisa

            # Create Razorpay order
            order_data = {
                'amount': amount_in_paisa,
                'currency': 'INR',
                'receipt': f'job_{job.job_id}_app_{application_id}_initial',
                'payment_capture': 1  # Auto-capture payment
            }
            razorpay_order = client.order.create(data=order_data)

            # Create Payment record
            payment = Payment.objects.create(
                job_application=application,
                payment_type='initial',
                razorpay_order_id=razorpay_order['id'],
                amount=amount,
                status='created'
            )
            conversation, created = Conversation.objects.get_or_create(job=job)
            # Return order details for frontend
            return Response({
                'message': 'Proceed to initial payment',
                'order_id': razorpay_order['id'],
                'amount': amount_in_paisa,
                'currency': 'INR',
                'key': settings.RAZORPAY_KEY_ID,
                'name': 'Your Company Name',
                'description': f'Initial Payment for Job: {job.title}',
                'application_id': application_id,
                'payment_type': 'initial'
            }, status=status.HTTP_200_OK)

        except JobApplication.DoesNotExist:
            return Response({'error': 'Application not found'}, status=status.HTTP_404_NOT_FOUND)
        except Job.DoesNotExist:
            return Response({'error': 'Job not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': f'Payment initiation failed: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
# accounts/views.py
class AdminVerifyProfessionalView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, professional_id):
        if not request.user.is_staff:
            return Response({'error': 'Only admins can verify professionals'}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            profile = ProfessionalProfile.objects.get(user__id=professional_id)
            return Response({
                'professional_name': profile.user.name,
                'verify_doc_url': profile.verify_doc.url if profile.verify_doc else None,
                'verify_status': profile.verify_status
            }, status=status.HTTP_200_OK)
        except ProfessionalProfile.DoesNotExist:
            return Response({'error': 'Profile not found'}, status=status.HTTP_404_NOT_FOUND)

    def post(self, request, professional_id):
        if not request.user.is_staff:
            return Response({'error': 'Only admins can verify professionals'}, status=status.HTTP_403_FORBIDDEN)
        
        try:
            profile = ProfessionalProfile.objects.get(user__id=professional_id)
            action = request.data.get('action')  # 'verify' or 'deny'
            
            if action == 'verify':
                profile.verify_status = 'Verified'
                profile.denial_reason = None  # Clear any previous denial reason
            elif action == 'deny':
                profile.verify_status = 'Not Verified'
                profile.denial_reason = request.data.get('denial_reason', 'No reason provided')
            else:
                return Response({'error': 'Invalid action'}, status=status.HTTP_400_BAD_REQUEST)
            
            profile.save()
            
            # Notify professional with appropriate message
            message = f"Your verification request has been {action}ed by the admin."
            if action == 'deny' and profile.denial_reason:
                message += f"\nReason: {profile.denial_reason}"
            
            send_mail(
                subject="Verification Status Update",
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[profile.user.email],
            )
            return Response({'message': f'Professional {action}ed successfully'}, status=status.HTTP_200_OK)
        except ProfessionalProfile.DoesNotExist:
            return Response({'error': 'Profile not found'}, status=status.HTTP_404_NOT_FOUND)
class AdminVerificationRequestsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if not request.user.is_superuser:
            return Response({'error': 'Only admins can view verification requests'}, status=status.HTTP_403_FORBIDDEN)
        
        pending_profiles = ProfessionalProfile.objects.filter(~Q(verify_status='Verified')).select_related('user')
        serializer = ProfessionalProfileSerializer(pending_profiles, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        if not request.user.is_superuser:
            return Response({'error': 'Only admins can verify professionals'}, status=status.HTTP_403_FORBIDDEN)
        
        professional_id = request.data.get('professional_id')
        action = request.data.get('action')  # 'verify' or 'deny'
        
        try:
            profile = ProfessionalProfile.objects.get(user__id=professional_id)
            if profile.verify_status != 'Pending':
                return Response({'error': 'This profile is not pending verification'}, status=status.HTTP_400_BAD_REQUEST)
            
            if action == 'verify':
                profile.verify_status = 'Verified'
                profile.denial_reason = None  # Clear any previous denial reason
            elif action == 'deny':
                profile.verify_status = 'Not Verified'
                profile.denial_reason = request.data.get('denial_reason', 'No reason provided')
            else:
                return Response({'error': 'Invalid action'}, status=status.HTTP_400_BAD_REQUEST)
            
            profile.save()
            
            # Notify professional with appropriate message
            message = f"Your verification request has been {action}ed by the admin."
            if action == 'deny' and profile.denial_reason:
                message += f"\nReason: {profile.denial_reason}"
            
            send_mail(
                subject="Verification Status Update",
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[profile.user.email],
            )
            return Response({'message': f'Professional {action}ed successfully'}, status=status.HTTP_200_OK)
        except ProfessionalProfile.DoesNotExist:
            return Response({'error': 'Profile not found'}, status=status.HTTP_404_NOT_FOUND)
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from .models import JobApplication
from .serializers import JobApplicationSerializer

class ProfessionalJobApplicationsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        if request.user.role != 'professional':
            return Response(
                {'error': 'Only professionals can view their job applications'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        applications = JobApplication.objects.filter(professional_id=request.user)
        serializer = JobApplicationSerializer(applications, many=True, context={'request': request})
        return Response({
            'applications': serializer.data
        }, status=status.HTTP_200_OK)

    def post(self, request):
        action = request.data.get('action')  # 'complete' or 'cancel'
        application_id = request.data.get('application_id')
        
        if not application_id or not action:
            return Response({'error': 'Application ID and action are required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            application = JobApplication.objects.get(
                application_id=application_id,
                professional_id=request.user
            )
            job = application.job_id

            if action == 'complete':
                if application.status != 'Accepted' or job.status != 'Assigned':
                    return Response(
                        {'error': 'This job is not currently assigned to you'},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                # Check if initial payment exists
                initial_payment = Payment.objects.filter(
                    job_application=application,
                    payment_type='initial',
                    status='completed'
                ).first()
                if not initial_payment:
                    return Response(
                        {'error': 'Initial payment not completed'},
                        status=status.HTTP_400_BAD_REQUEST
                    )

                # Calculate remaining payment with precise Decimal values
                initial_amount = Decimal(str(initial_payment.amount))
                job_budget = Decimal(str(job.budget))
                remaining_amount = job_budget - initial_amount
                
                # Debug logging
                print(f"Debug: job_budget={job_budget}, initial_amount={initial_amount}, remaining_amount={remaining_amount}")
                
                if remaining_amount <= Decimal('0'):
                    # If no remaining amount, complete the job directly
                    application.status = 'Completed'
                    job.status = 'Completed'
                    application.save()
                    job.save()
                    return Response(
                        {'message': 'Job marked as completed successfully'},
                        status=status.HTTP_200_OK
                    )

                # Initialize Razorpay client
                client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))

                # Convert to paisa with proper rounding
                amount_in_paisa = int(remaining_amount * 100)
                
                # Debug logging
                print(f"Debug: amount_in_paisa={amount_in_paisa}")

                # Create Razorpay order for remaining payment
                order_data = {
                    'amount': amount_in_paisa,
                    'currency': 'INR',
                    'receipt': f'job_{job.job_id}_app_{application_id}_remaining',
                    'payment_capture': 1
                }
                razorpay_order = client.order.create(data=order_data)

                # Create Payment record
                payment = Payment.objects.create(
                    job_application=application,
                    payment_type='remaining',
                    razorpay_order_id=razorpay_order['id'],
                    amount=remaining_amount,
                    status='created'
                )

                # Create PaymentRequest for client
                payment_request = PaymentRequest.objects.create(
                    payment=payment,
                    client=job.client_id,
                    status='pending'
                )

                # Log for debugging
                print(f"Created PaymentRequest: ID={payment_request.request_id}, PaymentID={payment.id}, Client={job.client_id.email}")

                # Send email notification to client (optional)
                
                # Return response indicating payment is pending
                return Response({
                    'message': 'Payment request sent to client',
                    'application_id': application_id,
                    'payment_type': 'remaining'
                }, status=status.HTTP_200_OK)

            elif action == 'cancel':
                if application.status != 'Accepted' or job.status != 'Assigned':
                    return Response(
                        {'error': 'This job is not currently assigned to you'},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                application.status = 'Cancelled'
                job.status = 'Open'
                application.save()
                job.save()
                return Response(
                    {'message': 'Job cancelled successfully'},
                    status=status.HTTP_200_OK
                )

            else:
                return Response({'error': 'Invalid action'}, status=status.HTTP_400_BAD_REQUEST)

        except JobApplication.DoesNotExist:
            return Response({'error': 'Application not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            print(f"Error in ProfessionalJobApplicationsView: {str(e)}")
            return Response({'error': f'An error occurred: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
class VerifyPaymentView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            # Get payment details from frontend
            razorpay_payment_id = request.data.get('razorpay_payment_id')
            razorpay_order_id = request.data.get('razorpay_order_id')
            razorpay_signature = request.data.get('razorpay_signature')
            application_id = request.data.get('application_id')
            payment_type = request.data.get('payment_type')  # 'initial' or 'remaining'

            if not all([razorpay_payment_id, razorpay_order_id, razorpay_signature, application_id, payment_type]):
                return Response({'error': 'Missing payment details'}, status=status.HTTP_400_BAD_REQUEST)

            # Verify payment signature
            client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_KEY_SECRET))
            params_dict = {
                'razorpay_order_id': razorpay_order_id,
                'razorpay_payment_id': razorpay_payment_id,
                'razorpay_signature': razorpay_signature
            }
            client.utility.verify_payment_signature(params_dict)

            # Get payment and application
            payment = get_object_or_404(Payment, razorpay_order_id=razorpay_order_id)
            application = get_object_or_404(JobApplication, application_id=application_id)
            job = application.job_id

            # Check if the user is the client
            if request.user != job.client_id:
                return Response(
                    {'error': 'You are not authorized to verify this payment'},
                    status=status.HTTP_403_FORBIDDEN
                )

            # Check if payment is already processed
            if payment.status != 'created':
                return Response(
                    {'error': 'Payment already processed'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Update payment record
            payment.razorpay_payment_id = razorpay_payment_id
            payment.razorpay_signature = razorpay_signature
            payment.status = 'completed'
            payment.save()

            # Update based on payment type
            if payment_type == 'initial':
                # Initial payment: Accept application and assign job
                application.status = 'Accepted'
                job.status = 'Assigned'
                job.professional_id = application.professional_id
                application.save()
                job.save()
                # Reject other applications
                JobApplication.objects.filter(job_id=job, status='Applied').exclude(application_id=application_id).update(status='Rejected')
                message = 'Initial payment verified and application accepted successfully'
            elif payment_type == 'remaining':
                # Remaining payment: Complete the job
                application.status = 'Completed'
                job.status = 'Completed'
                application.save()
                job.save()
                message = 'Remaining payment verified and job completed successfully'
            else:
                return Response({'error': 'Invalid payment type'}, status=status.HTTP_400_BAD_REQUEST)
            # Add this to the VerifyPaymentView class in views.py
# Inside the post method, after payment verification is successful

# Create notification for the professional
            professional = application.professional_id
            notification_data = {
                'job_id': job.job_id,
                'job_title': job.title,
                'payment_type': payment_type,
                'amount': str(payment.amount),  # Convert to string for JSON serialization
                'client_name': request.user.name,
                'client_id': request.user.id
            }

            # Create persistent notification in database
            notification = Notification.objects.create(
                user=professional,
                notification_type='payment',
                title=f"{'Initial' if payment_type == 'initial' else 'Final'} payment received",
                message=f"{request.user.name} has made the {'initial' if payment_type == 'initial' else 'final'} payment for job: {job.title}",
                data=notification_data,
                is_read=False
            )

            # Send real-time notification via WebSocket
            try:
                channel_layer = get_channel_layer()
                
                # Prepare notification data
                ws_notification_data = {
                    'type': 'payment',
                    'payment_type': payment_type,
                    'job_id': job.job_id,
                    'job_title': job.title,
                    'client_id': request.user.id,
                    'client_name': request.user.name,
                    'amount': str(payment.amount),
                    'timestamp': timezone.now().isoformat(),
                    'notification_id': str(notification.id)
                }
                
                # Send notification to professional's notification group
                async_to_sync(channel_layer.group_send)(
                    f'notifications_{professional.id}',
                    {
                        'type': 'send_notification',
                        'content': ws_notification_data
                    }
                )
                print(f"Sent WebSocket notification to professional {professional.id} about payment {payment.id}")
            except Exception as e:
                print(f"Failed to send WebSocket notification: {str(e)}")
            return Response({'message': message}, status=status.HTTP_200_OK)

        except razorpay.errors.SignatureVerificationError:
            return Response({'error': 'Invalid payment signature'}, status=status.HTTP_400_BAD_REQUEST)
        except Payment.DoesNotExist:
            return Response({'error': 'Payment record not found'}, status=status.HTTP_404_NOT_FOUND)
        except JobApplication.DoesNotExist:
            return Response({'error': 'Application not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': f'Payment verification failed: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
# accounts/views.py
class SubmitReviewView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        if user.role != 'client':
            return Response({'error': 'Unauthorized'}, status=status.HTTP_401_UNAUTHORIZED)

        job_id = request.data.get('job_id')
        rating = request.data.get('rating')
        review = request.data.get('review', '').strip()  # Get review, default to empty string

        if not job_id or not rating:
            return Response({'error': 'Job ID and rating are required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            rating = int(rating)
            if rating < 1 or rating > 5:
                raise ValueError('Rating must be between 1 and 5')
        except (ValueError, TypeError):
            return Response({'error': 'Invalid rating value'}, status=status.HTTP_400_BAD_REQUEST)

        # Validate review length (optional, e.g., max 500 characters)
        if len(review) > 500:
            return Response({'error': 'Review cannot exceed 500 characters'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            job = Job.objects.get(job_id=job_id, client_id=user, status='Completed')
        except Job.DoesNotExist:
            return Response({'error': 'Job not found or not completed'}, status=status.HTTP_404_NOT_FOUND)

        # Save both rating and review
        job.rating = rating
        job.review = review if review else None  # Save as None if empty
        job.save()

        # Update professional's avg_rating
        try:
            application = JobApplication.objects.get(job_id=job, status='Completed')
            professional_profile = ProfessionalProfile.objects.get(user=application.professional_id)
            professional_profile.update_avg_rating()
        except (JobApplication.DoesNotExist, ProfessionalProfile.DoesNotExist) as e:
            print(f"Debug: Failed to update avg_rating: {str(e)}")
            pass

        return Response({'message': 'Rating and review submitted successfully'}, status=status.HTTP_200_OK)
class AdminJobsView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
       
        # Categorize jobs by status
         # Categorize jobs by status
        pending_jobs = Job.objects.filter( status='Open')
        active_jobs = Job.objects.filter( status='Assigned')
        completed_jobs = Job.objects.filter(status='Completed')

        # Serialize each category
        pending_serializer = JobSerializer(pending_jobs, many=True)
        active_serializer = JobSerializer(active_jobs, many=True)
        completed_serializer = JobSerializer(completed_jobs, many=True)

        return Response({
            'pending': pending_serializer.data,
            'active': active_serializer.data,
            'completed': completed_serializer.data
        }, status=status.HTTP_200_OK)
class ClientTransactionHistoryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            if request.user.role != 'client':
                return Response(
                    {'error': 'Only clients can view transaction history'},
                    status=status.HTTP_403_FORBIDDEN
                )

            # Fetch all payments associated with the client's jobs
            client_jobs = Job.objects.filter(client_id=request.user)
            job_applications = JobApplication.objects.filter(job_id__in=client_jobs).select_related('job_id', 'professional_id')
            payments = Payment.objects.filter(job_application__in=job_applications).order_by('-created_at')

            # Serialize the payments
            serializer = PaymentSerializer(payments, many=True, context={'request': request})
            return Response({'transactions': serializer.data}, status=status.HTTP_200_OK)

        except Exception as e:
            print(f"Error in ClientTransactionHistoryView: {str(e)}")
            return Response(
                {'error': f'Internal server error: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ProfessionalTransactionHistoryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            if request.user.role != 'professional':
                return Response(
                    {'error': 'Only professionals can view transaction history'},
                    status=status.HTTP_403_FORBIDDEN
                )

            # Fetch payments where the user is the professional in the job application
            job_applications = JobApplication.objects.filter(professional_id=request.user).select_related('job_id', 'job_id__client_id')
            payments = Payment.objects.filter(job_application__in=job_applications).order_by('-created_at')

            # Serialize the payments
            serializer = PaymentSerializer(payments, many=True, context={'request': request})
            return Response({'transactions': serializer.data}, status=status.HTTP_200_OK)

        except Exception as e:
            print(f"Error in ProfessionalTransactionHistoryView: {str(e)}")
            return Response(
                {'error': f'Internal server error: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )