from django.shortcuts import render
from django.conf import settings
from rest_framework import status
from rest_framework.response import Response
from rest_framework import generics, permissions
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.permissions import AllowAny
from account.models import CustomUser
from account.serializers import UserSerializer
from .serializers import  UserBlockSerializer,AdminVerificationSerializer
from account.models import Complaint,Job,JobApplication,Conversation,ProfessionalProfile
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from django.db.models import Q
from datetime import datetime, timedelta
import logging
from account.serializers import JobSerializer
logger = logging.getLogger(__name__)
from django.core.mail import send_mail
# Create your views here.
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
class AdminVerificationRequestsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        """Get all verification requests for admin review"""
        # Check if user is admin (using is_staff or role)
        if not (request.user.is_staff or getattr(request.user, 'role', None) == 'admin'):
            return Response(
                {'error': 'Only admin can view verification requests'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            # Get profiles that need verification (Pending) or have been denied (Not Verified)
            profiles = ProfessionalProfile.objects.filter(
                Q(verify_status='Pending') | Q(verify_status='Not Verified')
            ).select_related('user').order_by('-user__date_joined')
            
            logger.info(f"Found {profiles.count()} profiles for verification review")
            
            # Use the admin-specific serializer with Cloudinary support
            serializer = AdminVerificationSerializer(profiles, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Error fetching verification requests: {str(e)}")
            return Response(
                {'error': 'Failed to fetch verification requests'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class AdminVerifyProfessionalView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, professional_id):
        """Get specific professional verification details"""
        if not (request.user.is_staff or getattr(request.user, 'role', None) == 'admin'):
            return Response(
                {'error': 'Only admins can view professional details'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            # Get the professional user and profile
            professional_user = CustomUser.objects.get(id=professional_id, role='professional')
            profile = ProfessionalProfile.objects.get(user=professional_user)
            
            # Use the admin serializer to get all details including Cloudinary URLs
            serializer = AdminVerificationSerializer(profile)
            return Response(serializer.data, status=status.HTTP_200_OK)
            
        except CustomUser.DoesNotExist:
            return Response(
                {'error': 'Professional not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )
        except ProfessionalProfile.DoesNotExist:
            return Response(
                {'error': 'Professional profile not found'}, 
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Error fetching professional details: {str(e)}")
            return Response(
                {'error': 'Failed to fetch professional details'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def post(self, request, professional_id):
        """Verify or deny a professional"""
        if not (request.user.is_staff or getattr(request.user, 'role', None) == 'admin'):
            return Response(
                {'error': 'Only admins can verify professionals'}, 
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            # Get the professional user and profile
            try:
                professional_user = CustomUser.objects.get(id=professional_id, role='professional')
                profile = ProfessionalProfile.objects.get(user=professional_user)
            except CustomUser.DoesNotExist:
                return Response(
                    {'error': 'Professional not found'}, 
                    status=status.HTTP_404_NOT_FOUND
                )
            except ProfessionalProfile.DoesNotExist:
                return Response(
                    {'error': 'Professional profile not found'}, 
                    status=status.HTTP_404_NOT_FOUND
                )
            
            action = request.data.get('action')
            
            if action == 'verify':
                # Check if verification document exists in Cloudinary
                if not profile.verify_doc:
                    return Response(
                        {'error': 'Cannot verify professional without verification document'}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Test if document is accessible
                try:
                    document_url = profile.verify_doc.url
                    if not document_url:
                        raise Exception("Document URL is empty")
                    logger.info(f"Document verified at: {document_url}")
                except Exception as e:
                    logger.error(f"Document accessibility check failed: {str(e)}")
                    return Response(
                        {'error': 'Verification document is not accessible. Please ask the professional to re-upload.'}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Verify the professional
                profile.verify_status = 'Verified'
                profile.denial_reason = None  # Clear any previous denial reason
                profile.save()
                
                logger.info(f"Professional {professional_user.email} verified by admin {request.user.email}")
                
                # Send notification email (optional)
                try:
                    send_mail(
                        subject="Verification Status Update - Approved! 🎉",
                        message=f"Dear {professional_user.name},\n\nGreat news! Your professional verification has been approved by our admin team.\n\nYou now have access to all professional features on our platform.\n\nBest regards,\nThe Team",
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[professional_user.email],
                        fail_silently=True,
                    )
                    logger.info(f"Verification approval email sent to {professional_user.email}")
                except Exception as e:
                    logger.warning(f"Failed to send verification email: {str(e)}")
                
                return Response({
                    'message': f'Professional {professional_user.name} has been verified successfully'
                }, status=status.HTTP_200_OK)
                
            elif action == 'deny':
                denial_reason = request.data.get('denial_reason', '').strip()
                
                if not denial_reason:
                    return Response(
                        {'error': 'Denial reason is required when denying verification'}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                # Deny the professional
                profile.verify_status = 'Not Verified'
                profile.denial_reason = denial_reason
                profile.save()
                
                logger.info(f"Professional {professional_user.email} denied by admin {request.user.email}. Reason: {denial_reason}")
                
                # Send notification email (optional)
                try:
                    send_mail(
                        subject="Verification Status Update",
                        message=f"Dear {professional_user.name},\n\nYour verification request has been reviewed.\n\nStatus: Not Verified\nReason: {denial_reason}\n\nPlease review the feedback and submit a new verification request with the required corrections.\n\nBest regards,\nThe Team",
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[professional_user.email],
                        fail_silently=True,
                    )
                    logger.info(f"Verification denial email sent to {professional_user.email}")
                except Exception as e:
                    logger.warning(f"Failed to send denial email: {str(e)}")
                
                return Response({
                    'message': f'Professional {professional_user.name} verification has been denied'
                }, status=status.HTTP_200_OK)
            
            else:
                return Response(
                    {'error': 'Invalid action. Use "verify" or "deny"'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
                
        except Exception as e:
            logger.error(f"Error processing verification request: {str(e)}")
            return Response(
                {'error': 'An unexpected error occurred while processing the request'}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
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