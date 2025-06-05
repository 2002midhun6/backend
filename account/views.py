from django.shortcuts import render
from django.conf import settings
from rest_framework import status
from rest_framework.response import Response
from rest_framework import generics, permissions
from rest_framework.views import APIView
from django.contrib.auth import authenticate
from django.db.models import Q
from rest_framework.parsers import MultiPartParser, FormParser
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
from .serializers import UserSerializer,JobSerializer,JobApplicationSerializer
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
            
            # Set the absolute URL for the local file
            if message.file:
                file_url = f'/media/message/{message.file.name}'
                message.file_absolute_url = request.build_absolute_uri(file_url)
                message.save(update_fields=['file_absolute_url'])
                logger.info(f"Set file absolute URL: {message.file_absolute_url}")

            # Send WebSocket notification
            from channels.layers import get_channel_layer
            from asgiref.sync import async_to_sync
            channel_layer = get_channel_layer()
            room_group_name = f'chat_{job_id}'
            
            message_data = {
                'id': message.id,
                'sender': message.sender.id,
                'sender_name': message.sender.name,
                'sender_role': message.sender.role,
                'content': message.content,
                'file_url': message.file_absolute_url,
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
    parser_classes = [MultiPartParser, FormParser]  # Support file uploads

    def get(self, request):
        """Fetch the logged-in user's professional profile"""
        user = request.user
        
        if getattr(user, 'role', None) != 'professional':
            return Response(
                {'error': 'Only professionals can access profiles'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            profile = ProfessionalProfile.objects.get(user=user)
            serializer = ProfessionalProfileSerializer(profile)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except ProfessionalProfile.DoesNotExist:
            return Response({'error': 'Profile not found'}, status=status.HTTP_404_NOT_FOUND)

    def post(self, request):
        """Create a professional profile for the authenticated user"""
        user = request.user
        
        logger.info(f"POST /api/profile/ - User: {user.id}, Data: {request.data}")
        logger.info(f"POST /api/profile/ - Files: {request.FILES}")
        
        # Check authentication
        if not user.is_authenticated:
            return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)
        
        # Check user role
        if getattr(user, 'role', None) != 'professional':
            return Response({'error': 'Only professionals can create a profile'}, status=status.HTTP_403_FORBIDDEN)
        
        # Prevent duplicate profile creation
        if ProfessionalProfile.objects.filter(user=user).exists():
            return Response({'error': 'Profile already exists'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Test Cloudinary configuration before processing if file is uploaded
            if 'verify_doc' in request.FILES:
                try:
                    import cloudinary.api
                    cloudinary.api.ping()
                    logger.info("Cloudinary configuration verified for profile creation")
                except Exception as e:
                    logger.error(f"Cloudinary configuration error: {e}")
                    return Response(
                        {'error': f'File upload service error: {str(e)}'},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )

            # Create profile with serializer
            serializer = ProfessionalProfileSerializer(data=request.data, context={'request': request})
            if serializer.is_valid():
                profile = serializer.save(user=user)
                
                logger.info(f"Profile created successfully for user {user.id}")
                if profile.verify_doc:
                    logger.info(f"Verification document uploaded: {profile.verify_doc.url}")
                
                return Response({
                    'message': 'Profile created successfully',
                    'profile': ProfessionalProfileSerializer(profile).data
                }, status=status.HTTP_201_CREATED)
            else:
                logger.error(f"Profile creation failed with errors: {serializer.errors}")
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
                
        except Exception as e:
            logger.error(f"Unexpected error in profile creation: {str(e)}")
            return Response(
                {'error': 'An unexpected error occurred while creating the profile'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def patch(self, request):
        """Update the professional profile"""
        user = request.user
        
        logger.info(f"PATCH /api/profile/ - User: {user.id}, Data: {request.data}")
        logger.info(f"PATCH /api/profile/ - Files: {request.FILES}")

        if not user.is_authenticated:
            return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)

        if getattr(user, 'role', None) != 'professional':
            return Response({'error': 'Only professionals can update a profile'}, status=status.HTTP_403_FORBIDDEN)

        try:
            profile = ProfessionalProfile.objects.get(user=user)
            
            # Test Cloudinary configuration before processing if file is uploaded
            if 'verify_doc' in request.FILES:
                try:
                    import cloudinary.api
                    cloudinary.api.ping()
                    logger.info("Cloudinary configuration verified for profile update")
                except Exception as e:
                    logger.error(f"Cloudinary configuration error: {e}")
                    return Response(
                        {'error': f'File upload service error: {str(e)}'},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )
            
            serializer = ProfessionalProfileSerializer(profile, data=request.data, partial=True, context={'request': request})
            if serializer.is_valid():
                updated_profile = serializer.save()
                
                logger.info(f"Profile updated successfully for user {user.id}")
                if updated_profile.verify_doc:
                    logger.info(f"Verification document uploaded/updated: {updated_profile.verify_doc.url}")
                
                return Response({
                    'message': 'Profile updated successfully',
                    'profile': ProfessionalProfileSerializer(updated_profile).data
                }, status=status.HTTP_200_OK)
            else:
                logger.error(f"Profile update failed with errors: {serializer.errors}")
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
                
        except ProfessionalProfile.DoesNotExist:
            return Response(
                {'error': 'Profile not found. Please create a profile first.'}, 
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Unexpected error in profile update: {str(e)}")
            return Response(
                {'error': 'An unexpected error occurred while updating the profile'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def delete(self, request):
        """Delete the professional profile"""
        user = request.user
        
        if not user.is_authenticated:
            return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)

        if getattr(user, 'role', None) != 'professional':
            return Response({'error': 'Only professionals can delete a profile'}, status=status.HTTP_403_FORBIDDEN)

        try:
            profile = ProfessionalProfile.objects.get(user=user)
            
            # The signal will handle Cloudinary file deletion
            profile.delete()
            
            logger.info(f"Profile deleted successfully for user {user.id}")
            return Response({
                'message': 'Profile deleted successfully'
            }, status=status.HTTP_200_OK)
            
        except ProfessionalProfile.DoesNotExist:
            return Response(
                {'error': 'Profile not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )
class JobCreateView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]  # NEW: Support file uploads

    def post(self, request):
        if request.user.role != 'client':
            return Response(
                {'error': 'Only clients can post jobs'},
                status=status.HTTP_403_FORBIDDEN
            )

        try:
            # Log the incoming data for debugging
            logger.info(f"Received job creation request from user {request.user.id}")
            logger.info(f"Files in request: {request.FILES}")
            logger.info(f"Data in request: {request.data}")

            serializer = JobSerializer(data=request.data, context={'request': request})
            if serializer.is_valid():
                job = serializer.save(client_id=request.user)
                
                # Log successful creation
                logger.info(f"Job created successfully with ID: {job.job_id}")
                if job.document:
                    logger.info(f"Document uploaded: {job.document.url}")
                
                return Response(
                    serializer.data,
                    status=status.HTTP_201_CREATED
                )
            else:
                logger.error(f"Job creation failed with errors: {serializer.errors}")
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
                
        except Exception as e:
            logger.error(f"Unexpected error in job creation: {str(e)}")
            return Response(
                {'error': 'An unexpected error occurred while creating the job'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
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

# Update your JobDetailView in views.py to support file uploads for editing

from rest_framework.parsers import MultiPartParser, FormParser

class JobDetailView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]  # Add parsers for file upload

    def get(self, request, job_id):
        """Get job details"""
        if request.user.role != 'client':
            return Response(
                {'error': 'Only clients can view job details'},
                status=status.HTTP_403_FORBIDDEN
            )

        job = get_object_or_404(Job, job_id=job_id, client_id=request.user)
        serializer = JobSerializer(job, context={'request': request})
        return Response(serializer.data)

    def put(self, request, job_id):
        """Update/Edit job - only allowed if no applicants"""
        if request.user.role != 'client':
            return Response(
                {'error': 'Only clients can edit jobs'},
                status=status.HTTP_403_FORBIDDEN
            )

        job = get_object_or_404(Job, job_id=job_id, client_id=request.user)
        
        # Check if job is still open
        if job.status != 'Open':
            return Response(
                {'error': 'Only open projects can be edited'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if there are any applicants
        applicants_count = job.applications.count()
        if applicants_count > 0:
            return Response(
                {'error': f'Cannot edit project with {applicants_count} applicant(s). Projects can only be edited when there are no applicants.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Log the incoming data for debugging
            logger.info(f"Received job edit request from user {request.user.id} for job {job_id}")
            logger.info(f"Files in request: {request.FILES}")
            logger.info(f"Data in request: {request.data}")

            # Handle file removal - if attachment is explicitly set to null/empty
            if 'document' in request.data and (request.data['document'] == 'null' or request.data['document'] == ''):
                # Create a copy of request data and remove the document
                mutable_data = request.data.copy()
                mutable_data['document'] = None
                serializer = JobSerializer(job, data=mutable_data, partial=True, context={'request': request})
            else:
                # Validate and update the job normally
                serializer = JobSerializer(job, data=request.data, partial=True, context={'request': request})
            
            if serializer.is_valid():
                updated_job = serializer.save()
                
                # Log successful update
                logger.info(f"Job {job_id} updated successfully")
                if updated_job.document:
                    logger.info(f"Document uploaded/updated: {updated_job.document.url}")
                else:
                    logger.info("No document attached or document was removed")
                
                return Response({
                    'message': 'Project updated successfully',
                    'job': serializer.data
                }, status=status.HTTP_200_OK)
            else:
                logger.error(f"Job update failed with errors: {serializer.errors}")
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
                
        except Exception as e:
            logger.error(f"Unexpected error in job update: {str(e)}")
            return Response(
                {'error': 'An unexpected error occurred while updating the job'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def delete(self, request, job_id):
        """Delete job - only allowed if no applicants"""
        if request.user.role != 'client':
            return Response(
                {'error': 'Only clients can delete jobs'},
                status=status.HTTP_403_FORBIDDEN
            )

        job = get_object_or_404(Job, job_id=job_id, client_id=request.user)
        
        # Check if job can be deleted (only open jobs)
        if job.status != 'Open':
            return Response(
                {'error': 'Only open projects can be deleted'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if there are any applicants
        applicants_count = job.applications.count()
        if applicants_count > 0:
            return Response(
                {'error': f'Cannot delete project with {applicants_count} applicant(s). Projects can only be deleted when there are no applicants.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Store job title for response message
        job_title = job.title
        
        # Delete the job (this will also delete the Cloudinary file via the signal)
        job.delete()
        
        return Response({
            'message': f'Project "{job_title}" has been successfully deleted'
        }, status=status.HTTP_200_OK)
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

from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from .models import JobApplication
from .serializers import JobApplicationSerializer

# views.py - Enhanced Professional Job Applications View

from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings
from .models import Notification

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

    def send_completion_notification_and_email(self, job, professional, client):
        """Send notification and email when project is completed"""
        try:
            # Create notification for client
            Notification.objects.create(
                user=client,
                notification_type='job_status',
                title='Project Completed! 🎉',
                message=f'Your project "{job.title}" has been marked as completed by {professional.name}.',
                data={
                    'job_id': job.job_id,
                    'professional_id': professional.id,
                    'professional_name': professional.name,
                    'job_title': job.title,
                    'action_required': 'review_and_rate'
                }
            )
            
            # Send email to client
            subject = f'Project Completed: {job.title}'
            
            # Create email context
            email_context = {
                'client_name': client.name,
                'professional_name': professional.name,
                'job_title': job.title,
                'job_description': job.description[:200] + '...' if len(job.description) > 200 else job.description,
                'budget': job.budget,
                'completion_date': timezone.now().strftime('%B %d, %Y'),
                'login_url': f"{settings.FRONTEND_URL}/login" if hasattr(settings, 'FRONTEND_URL') else "your-website.com/login",
                'project_url': f"{settings.FRONTEND_URL}/client-projects" if hasattr(settings, 'FRONTEND_URL') else "your-website.com/client-projects"
            }
            
            # HTML email template
            html_message = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                    .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
                    .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; }}
                    .content {{ background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px; }}
                    .highlight {{ background: #e3f2fd; padding: 15px; border-left: 4px solid #2196f3; margin: 20px 0; border-radius: 5px; }}
                    .button {{ display: inline-block; background: #28a745; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; margin: 10px 5px; }}
                    .project-details {{ background: white; padding: 20px; border-radius: 8px; margin: 20px 0; border: 1px solid #e0e0e0; }}
                    .footer {{ text-align: center; color: #666; margin-top: 30px; font-size: 14px; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🎉 Project Completed!</h1>
                        <p>Great news about your project</p>
                    </div>
                    
                    <div class="content">
                        <p>Dear {email_context['client_name']},</p>
                        
                        <div class="highlight">
                            <strong>Excellent news!</strong> Your project has been successfully completed by {email_context['professional_name']}.
                        </div>
                        
                        <div class="project-details">
                            <h3>📋 Project Details</h3>
                            <p><strong>Project:</strong> {email_context['job_title']}</p>
                            <p><strong>Professional:</strong> {email_context['professional_name']}</p>
                            <p><strong>Budget:</strong> ₹{email_context['budget']}</p>
                            <p><strong>Completed on:</strong> {email_context['completion_date']}</p>
                            <p><strong>Description:</strong> {email_context['job_description']}</p>
                        </div>
                        
                        <h3>🎯 Next Steps:</h3>
                        <ul>
                            <li>Review the completed work</li>
                            <li>Rate and review the professional's performance</li>
                            <li>Complete any remaining payment if applicable</li>
                        </ul>
                        
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="{email_context['project_url']}" class="button">View Project Details</a>
                            <a href="{email_context['login_url']}" class="button" style="background: #17a2b8;">Login to Dashboard</a>
                        </div>
                        
                        <p>Thank you for using our platform! We hope you had a great experience working with {email_context['professional_name']}.</p>
                        
                        <div class="footer">
                            <p>This is an automated notification. Please do not reply to this email.</p>
                            <p>If you have any questions, please contact our support team.</p>
                        </div>
                    </div>
                </div>
            </body>
            </html>
            """
            
            # Plain text version
            plain_message = f"""
            Project Completed!
            
            Dear {email_context['client_name']},
            
            Great news! Your project "{email_context['job_title']}" has been successfully completed by {email_context['professional_name']}.
            
            Project Details:
            - Project: {email_context['job_title']}
            - Professional: {email_context['professional_name']}
            - Budget: ₹{email_context['budget']}
            - Completed on: {email_context['completion_date']}
            
            Next Steps:
            1. Review the completed work
            2. Rate and review the professional's performance
            3. Complete any remaining payment if applicable
            
            Please log in to your dashboard to view the project details and provide your feedback.
            
            Thank you for using our platform!
            
            Best regards,
            The Team
            """
            
            # Send email
            send_mail(
                subject=subject,
                message=plain_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[client.email],
                html_message=html_message,
                fail_silently=False
            )
            
            print(f"✅ Completion notification and email sent to {client.email}")
            
        except Exception as e:
            print(f"❌ Error sending completion notification/email: {str(e)}")
            # Don't fail the main operation if notification fails

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
                    
                    # 🚀 Send completion notification and email to client
                    self.send_completion_notification_and_email(
                        job=job,
                        professional=request.user,
                        client=job.client_id
                    )
                    
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

                # 📧 Send payment request notification and email to client
                try:
                    # Create notification for payment request
                    Notification.objects.create(
                        user=job.client_id,
                        notification_type='payment',
                        title='Payment Request - Project Completion',
                        message=f'{request.user.name} has completed your project "{job.title}" and is requesting the remaining payment of ₹{remaining_amount}.',
                        data={
                            'job_id': job.job_id,
                            'payment_request_id': payment_request.request_id,
                            'amount': str(remaining_amount),
                            'payment_type': 'remaining',
                            'action_required': 'complete_payment'
                        }
                    )
                    
                    # Send payment request email
                    payment_subject = f'Payment Request: {job.title}'
                    payment_message = f"""
                    Dear {job.client_id.name},
                    
                    Good news! {request.user.name} has successfully completed your project "{job.title}".
                    
                    A remaining payment of ₹{remaining_amount} is now due. Please log in to your dashboard to complete the payment.
                    
                    Project Details:
                    - Project: {job.title}
                    - Professional: {request.user.name}
                    - Remaining Amount: ₹{remaining_amount}
                    
                    Thank you!
                    """
                    
                    send_mail(
                        subject=payment_subject,
                        message=payment_message,
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[job.client_id.email],
                        fail_silently=True
                    )
                    
                except Exception as e:
                    print(f"Error sending payment request notification: {str(e)}")

                # Log for debugging
                print(f"Created PaymentRequest: ID={payment_request.request_id}, PaymentID={payment.id}, Client={job.client_id.email}")

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
                
                # Update status
                application.status = 'Cancelled'
                job.status = 'Open'
                application.save()
                job.save()
                
                # 📧 Send cancellation notification to client
                try:
                    Notification.objects.create(
                        user=job.client_id,
                        notification_type='job_status',
                        title='Project Cancelled',
                        message=f'{request.user.name} has cancelled your project "{job.title}". The project is now open for new applications.',
                        data={
                            'job_id': job.job_id,
                            'professional_id': request.user.id,
                            'professional_name': request.user.name,
                            'job_title': job.title,
                            'action_required': 'find_new_professional'
                        }
                    )
                    
                    # Send cancellation email
                    cancellation_subject = f'Project Cancelled: {job.title}'
                    cancellation_message = f"""
                    Dear {job.client_id.name},
                    
                    We regret to inform you that {request.user.name} has cancelled your project "{job.title}".
                    
                    Your project is now open again and you can receive new applications from other professionals.
                    
                    If you have any questions, please contact our support team.
                    
                    Best regards,
                    The Team
                    """
                    
                    send_mail(
                        subject=cancellation_subject,
                        message=cancellation_message,
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[job.client_id.email],
                        fail_silently=True
                    )
                    
                except Exception as e:
                    print(f"Error sending cancellation notification: {str(e)}")
                
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
from django.http import HttpResponse, Http404, FileResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
import os
from pathlib import Path
from .models import Message, JobApplication

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def serve_message_file(request, file_path):
    """
    Securely serve message files with permission checking
    """
    try:
        # Reconstruct the full file path
        full_path = os.path.join(settings.MEDIA_ROOT, 'message', file_path)
        
        # Security check - ensure the path is within our media directory
        media_path = Path(settings.MEDIA_ROOT).resolve()
        file_path_resolved = Path(full_path).resolve()
        
        if not str(file_path_resolved).startswith(str(media_path)):
            raise Http404("File not found")
        
        if not os.path.exists(full_path):
            raise Http404("File not found")
        
        # Find the message that owns this file
        # Extract the filename from the path
        filename = os.path.basename(file_path)
        message = Message.objects.filter(file__icontains=filename).first()
        
        if not message:
            raise Http404("File not found")
        
        # Check permissions
        conversation = message.conversation
        job = conversation.job
        
        # User must be either the client or an accepted professional
        if request.user != job.client_id:
            application = JobApplication.objects.filter(
                job_id=job,
                professional_id=request.user,
                status='Accepted'
            ).first()
            if not application:
                raise Http404("File not found")
        
        # Serve the file
        return FileResponse(
            open(full_path, 'rb'),
            as_attachment=False,
            filename=os.path.basename(full_path)
        )
        
    except Exception as e:
        raise Http404("File not found")

# Add this to your account/urls.py
# path('media/message/<path:file_path>', views.serve_message_file, name='serve_message_file'),