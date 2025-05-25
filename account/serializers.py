# accounts/serializers.py
from rest_framework import serializers
from .models import CustomUser,ProfessionalProfile,JobApplication
from .models import Job
from backend.utils import send_otp_email
import random
from django.utils.timezone import now
from django.core.mail import send_mail
from django.conf import settings
from .models import Payment
from datetime import date
from .models import Complaint,Conversation,Message
from rest_framework import serializers
from .models import Message

from .models import Notification

class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = ['id', 'notification_type', 'title', 'message', 'data', 'is_read', 'created_at']
        read_only_fields = ['id', 'notification_type', 'title', 'message', 'data', 'created_at']
class MessageSerializer(serializers.ModelSerializer):
    sender_name = serializers.SerializerMethodField()
    sender_role = serializers.SerializerMethodField()
    file_url = serializers.SerializerMethodField()
    
    class Meta:
        model = Message
        fields = ['id', 'sender', 'sender_name', 'sender_role', 'content', 'file_url', 'file_type', 'created_at', 'is_read']
    
    def get_sender_name(self, obj):
        return obj.sender.name if hasattr(obj.sender, 'name') else str(obj.sender)
    
    def get_sender_role(self, obj):
        return obj.sender.role if hasattr(obj.sender, 'role') else 'unknown'
    
    def get_file_url(self, obj):
        if obj.file_absolute_url:
            return obj.file_absolute_url
        elif obj.file:
            request = self.context.get('request')
            if request:
                return request.build_absolute_uri(obj.file.url)
            return obj.file.url
        return None

class ConversationSerializer(serializers.ModelSerializer):
    messages = MessageSerializer(many=True, read_only=True)
    job_title = serializers.CharField(source='job.title', read_only=True)
    client_id = serializers.IntegerField(source='job.client_id.id', read_only=True, allow_null=True)
    professional_id = serializers.IntegerField(source='job.professional_id.id', read_only=True, allow_null=True)

    class Meta:
        model = Conversation
        fields = ['id', 'job', 'job_title', 'client_id', 'professional_id', 'messages', 'created_at']

class ComplaintSerializer(serializers.ModelSerializer):
    user_email = serializers.SerializerMethodField()
    user_role = serializers.SerializerMethodField()
    status_display = serializers.SerializerMethodField()
    
    class Meta:
        model = Complaint
        fields = [
            'id', 
            'user', 
            'user_email',
            'user_role',
            'description', 
            'status', 
            'status_display',
            'created_at', 
            'updated_at'
        ]
        read_only_fields = ['id', 'user', 'user_email', 'user_role', 'created_at', 'updated_at', 'status_display']
    
    def get_user_email(self, obj):
        return obj.user.email if obj.user else None
    
    def get_user_role(self, obj):
        return obj.user.role if obj.user else None
    
    def get_status_display(self, obj):
        return obj.get_status_display()
    
    def create(self, validated_data):
        # Associate complaint with the current user
        user = self.context['request'].user
        validated_data['user'] = user
        return super().create(validated_data)
class PaymentSerializer(serializers.ModelSerializer):
    job_application = serializers.SerializerMethodField()

    class Meta:
        model = Payment
        fields = ['razorpay_order_id', 'amount', 'payment_type', 'job_application']

    def get_job_application(self, obj):
        try:
            if obj.job_application:
                return {
                    'id': obj.job_application.application_id,
                    'job_title': obj.job_application.job_id.title if obj.job_application.job_id else 'Unknown Job',
                    'professional_name': obj.job_application.professional_id.name if obj.job_application.professional_id else 'Unknown Professional',
                    'client_name': obj.job_application.job_id.client_id.name if obj.job_application.job_id.client_id else 'Unknown Client',
                    'status': obj.job_application.status,
                }
            return {
                'id': None,
                'job_title': 'Unknown Job',
                'professional_name': 'Unknown Professional',
                'client_name': 'Unknown Client',
                'status': 'N/A',
            }
        except Exception as e:
            print(f"Error in PaymentSerializer.get_job_application: {str(e)}")
            return {
                'id': None,
                'job_title': 'Unknown Job',
                'professional_name': 'Unknown Professional',
                'client_name': 'Unknown Client',
                'status': 'N/A',
            }

    def to_representation(self, instance):
        try:
            representation = super().to_representation(instance)
            
            # Always convert amount to paisa for Razorpay
            representation['amount'] = int(float(instance.amount) * 100) if instance.amount else 0
            representation['order_id'] = instance.razorpay_order_id
            representation['key'] = settings.RAZORPAY_KEY_ID
            representation['name'] = 'Your Company Name'
            representation['currency'] = 'INR'
            
            if instance.payment_type == 'initial':
                payment_desc = 'Initial Payment'
            else:
                payment_desc = 'Remaining Payment'
                
            # Use nested job_application.job_title for description
            job_title = representation.get('job_application', {}).get('job_title', 'Unknown Job')
            representation['description'] = f'{payment_desc} for Job: {job_title}'
            
            # Debug log
            print(f"PaymentSerializer debug: Original amount={instance.amount}, Converted amount={representation['amount']}")
            
            return representation
        except Exception as e:
            print(f"Error in PaymentSerializer.to_representation: {str(e)}")
            return super().to_representation(instance)
class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    
    class Meta:
        model = CustomUser
        fields = ['email', 'name', 'role', 'password']
        
    def create(self, validated_data):
        user = CustomUser.objects.create_user(
            email=validated_data['email'],
            name=validated_data['name'],
            role=validated_data['role'],
            password=validated_data['password']
        )
        return user

class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()


class OTPVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)

    def validate(self, data):
        try:
            user = CustomUser.objects.get(email=data['email'])
            if user.otp != data['otp']:
                raise serializers.ValidationError("Invalid OTP.")
            user.is_active = True  # Activate user
            user.is_verified = True
            user.otp = None  # Remove OTP after verification
            user.save()
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("User not found.")
        return data
class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate(self, data):
        try:
            user = CustomUser.objects.get(email=data['email'])
            # Generate a new OTP for password reset
            user.otp = str(random.randint(100000, 999999))
            user.otp_created_at = now()
            user.save()
            send_otp_email(user)  # Reuse the existing send_otp_email function
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("No account found with this email.")
        return data

# Reset Password Serializer
class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(max_length=6)
    new_password = serializers.CharField(write_only=True)

    def validate(self, data):
        try:
            user = CustomUser.objects.get(email=data['email'])
            if not user.otp:
                raise serializers.ValidationError("No OTP requested for this account.")
            if user.otp != data['otp']:
                raise serializers.ValidationError("Invalid OTP.")
            if user.otp_created_at and (now() - user.otp_created_at).total_seconds() > 600:
                raise serializers.ValidationError("OTP has expired.")
        except CustomUser.DoesNotExist:
            raise serializers.ValidationError("User not found.")
        return data
    def save(self):
        user = CustomUser.objects.get(email=self.validated_data['email'])
        user.set_password(self.validated_data['new_password'])
        user.otp = None
        user.otp_created_at = None
        user.save()
        return user

class UserBlockSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['is_blocked']
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['id', 'email', 'name', 'role', 'is_blocked', 'is_verified']
class ProfessionalProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    verify_doc = serializers.FileField(required=False)
    
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
            'denial_reason',
        ]
# accounts/serializers.py
class JobSerializer(serializers.ModelSerializer):
    client_id = serializers.SerializerMethodField()
    client_name = serializers.CharField(source='client_id.name', read_only=True)  # Added
    applicants_count = serializers.SerializerMethodField()

    class Meta:
        model = Job
        fields = [
            'job_id',
            'title',
            'description',
            'budget',
            'deadline',
            'status',
            'created_at',
            'advance_payment',
            'client_id',
            'client_name',  
            'applicants_count',
            'rating',
            'review'
        ]
        read_only_fields = ['job_id', 'status', 'created_at', 'client_id', 'client_name', 'applicants_count', 'rating']

    def get_client_id(self, obj):
        return UserSerializer(obj.client_id).data

    def get_applicants_count(self, obj):
        return obj.applications.count()

    def validate_budget(self, value):
        if value <= 0:
            raise serializers.ValidationError("Budget must be greater than zero")
        return value

    def validate_advance_payment(self, value):
        if value is not None and value < 0:
            raise serializers.ValidationError("Advance payment cannot be negative")
        return value

    def validate_deadline(self, value):
        if value < date.today():
            raise serializers.ValidationError("Deadline cannot be in the past")
        return value

    def validate(self, data):
        if 'advance_payment' in data and 'budget' in data and data['advance_payment'] is not None:
            if data['advance_payment'] > data['budget']:
                raise serializers.ValidationError("Advance payment cannot exceed budget")
        return data
class JobApplicationSerializer(serializers.ModelSerializer):
    professional_id = serializers.PrimaryKeyRelatedField(
        queryset=CustomUser.objects.filter(role='professional'),
        required=False
    )
    job_id = serializers.PrimaryKeyRelatedField(
        queryset=Job.objects.all()
    )
    job_details = serializers.SerializerMethodField()
    professional_details = serializers.SerializerMethodField()

    class Meta:
        model = JobApplication
        fields = ['application_id', 'job_id', 'professional_id', 'status', 'applied_at', 'professional_details', 'job_details']
        read_only_fields = ['application_id', 'applied_at', 'professional_details', 'job_details']

    def get_professional_details(self, obj):
        try:
            profile = ProfessionalProfile.objects.get(user=obj.professional_id)
            profile_data = ProfessionalProfileSerializer(profile).data
            user_data = UserSerializer(obj.professional_id).data
            return {**profile_data, 'user': user_data}
        except ProfessionalProfile.DoesNotExist:
            return {'user': UserSerializer(obj.professional_id).data}

    def get_job_details(self, obj):
        return JobSerializer(obj.job_id).data

    def validate(self, data):
        job = data['job_id']
        if job.status != 'Open':
            raise serializers.ValidationError("This job is not open for applications.")
        request_user = self.context['request'].user
        if JobApplication.objects.filter(job_id=job, professional_id=request_user).exists():
            raise serializers.ValidationError("You have already applied to this job.")
        return data
