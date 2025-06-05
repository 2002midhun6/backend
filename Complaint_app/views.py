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
from account.models import Complaint,CustomUser
from .serializers import ComplaintSerializer
from rest_framework.permissions import IsAuthenticated
from rest_framework.permissions import AllowAny
from django.utils import timezone
from account.models import Notification
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from backend.utils import send_otp_email
from django.core.mail import send_mail
# Create your views here.
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
        
        # Only allow clients to mark as resolved if status is AWAITING_USER_RESPONSE
        if 'status' in request.data:
            new_status = request.data['status']
            if new_status == 'RESOLVED' and complaint.status == 'AWAITING_USER_RESPONSE':
                # Client is marking as resolved - allow this
                pass
            elif user.is_superuser or user.is_staff:
                # Admin can update any status
                pass
            else:
                return Response(
                    {'error': 'You can only mark complaints as resolved when awaiting your response'},
                    status=status.HTTP_403_FORBIDDEN
                )
            
        return super().patch(request, *args, **kwargs)
class ComplaintFeedbackView(APIView):
    """
    View for submitting client feedback on admin responses
    """
    permission_classes = [IsAuthenticated]
    
    def patch(self, request, pk):
        try:
            complaint = Complaint.objects.get(id=pk, user=request.user)
        except Complaint.DoesNotExist:
            return Response(
                {'error': 'Complaint not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        # Validate that complaint can receive feedback
        if complaint.status != 'AWAITING_USER_RESPONSE':
            return Response(
                {'error': 'Cannot provide feedback for this complaint status'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        client_feedback = request.data.get('client_feedback', '').strip()
        resolution_rating = request.data.get('resolution_rating')
        
        if not client_feedback:
            return Response(
                {'error': 'Feedback text is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Validate rating if provided
        if resolution_rating is not None:
            try:
                resolution_rating = int(resolution_rating)
                if resolution_rating < 1 or resolution_rating > 5:
                    raise ValueError
            except (ValueError, TypeError):
                return Response(
                    {'error': 'Rating must be between 1 and 5'},
                    status=status.HTTP_400_BAD_REQUEST
                )
        
        # Update complaint with feedback
        complaint.client_feedback = client_feedback
        complaint.resolution_rating = resolution_rating
        complaint.feedback_date = timezone.now()
        complaint.status = 'NEEDS_FURTHER_ACTION'
        complaint.save()
        
        # Notify admin about the feedback
        try:
            # Create notification for admin staff
            admin_users = CustomUser.objects.filter(is_staff=True)
            for admin in admin_users:
                Notification.objects.create(
                    user=admin,
                    notification_type='complaint',
                    title=f'Complaint #{complaint.id} needs further action',
                    message=f'User {complaint.user.email} provided feedback on complaint response and needs further assistance.',
                    data={
                        'complaint_id': complaint.id,
                        'user_email': complaint.user.email,
                        'rating': resolution_rating,
                        'action_required': 'review_feedback'
                    }
                )
            
            
        except Exception as e:
            print(f"Error sending feedback notification: {str(e)}")
        
        serializer = ComplaintSerializer(complaint, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)
class AdminComplaintListView(generics.ListAPIView):
    """
    Admin view for listing all complaints with filtering options
    """
    serializer_class = ComplaintSerializer
    permission_classes = [IsAuthenticated]
    
    def get_permissions(self):
        if not (self.request.user.is_staff or self.request.user.is_superuser):
            return [IsAdminUser()]
        return super().get_permissions()
    
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
                Q(user__email__icontains=search) |
                Q(id__icontains=search)
            )
            
        return queryset
class AdminComplaintResponseView(APIView):
    """
    Admin view for responding to complaints
    """
    permission_classes = [IsAuthenticated]
    
    def patch(self, request, pk):
        if not (request.user.is_staff or request.user.is_superuser):
            return Response(
                {'error': 'Only admin users can respond to complaints'},
                status=status.HTTP_403_FORBIDDEN
            )
        
        try:
            complaint = Complaint.objects.get(id=pk)
        except Complaint.DoesNotExist:
            return Response(
                {'error': 'Complaint not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        
        admin_response = request.data.get('admin_response', '').strip()
        if not admin_response:
            return Response(
                {'error': 'Response text is required'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Update complaint with admin response
        complaint.admin_response = admin_response
        complaint.responded_by = request.user
        complaint.response_date = timezone.now()
        complaint.status = 'AWAITING_USER_RESPONSE'
        complaint.save()
        
        # Create notification for the user
        try:
            Notification.objects.create(
                user=complaint.user,
                notification_type='complaint',
                title=f'Response to your complaint #{complaint.id}',
                message=f'An admin has responded to your complaint. Please review the response and let us know if it resolves your issue.',
                data={
                    'complaint_id': complaint.id,
                    'response_preview': admin_response[:100] + '...' if len(admin_response) > 100 else admin_response,
                    'action_required': 'review_response'
                }
            )
            
            # Send email notification to user
            send_mail(
                subject=f'Response to Your Complaint #{complaint.id}',
                message=f"""
                Dear {complaint.user.name},
                
                We have reviewed your complaint and provided a response.
                
                Original Issue: {complaint.description[:200]}...
                
                Our Response: {admin_response}
                
                Please log in to your account to review the full response and let us know if this resolves your issue or if you need further assistance.
                
                Thank you for your patience.
                
                Best regards,
                Customer Support Team
                """,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[complaint.user.email],
                fail_silently=True
            )
        except Exception as e:
            print(f"Error sending response notification: {str(e)}")
        
        serializer = ComplaintSerializer(complaint, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)