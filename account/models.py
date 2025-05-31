# Create your models here.
# accounts/models.py

import random
import uuid
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.utils.timezone import now
from django.conf import settings
from django.core.validators import MinValueValidator, MaxValueValidator
from cloudinary.models import CloudinaryField
# Add this to your existing models.py file
from .storage import LocalFileStorage
class Notification(models.Model):
    NOTIFICATION_TYPES = [
        ('job_application', 'Job Application'),
        ('payment', 'Payment'),
        ('message', 'Message'),
        ('job_status', 'Job Status Change'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='notifications')
    notification_type = models.CharField(max_length=20, choices=NOTIFICATION_TYPES)
    title = models.CharField(max_length=255)
    message = models.TextField()
    data = models.JSONField(blank=True, null=True)  # Additional structured data
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.notification_type} - {self.title[:30]}"
class CustomUserManager(BaseUserManager):
    def create_user(self, email, name, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        extra_fields.setdefault("is_verified", False)
        extra_fields.setdefault("otp", str(random.randint(100000, 999999)))  # Generate OTP
        extra_fields.setdefault("otp_created_at", now())  # Store OTP timestamp
       
        extra_fields.setdefault("is_active", True)
        user = self.model(email=email, name=name, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, name, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)  # Ensure active
        extra_fields.setdefault("is_verified", True)  # Bypass verification
        extra_fields.setdefault("otp", None)
        extra_fields.setdefault("otp_created_at", None)
        # extra_fields.setdefault("role", None)
        return self.create_user(email, name, password, **extra_fields)

class CustomUser(AbstractUser):
    # Choices for role
    ROLE_CHOICES = (
        ('professional', 'Professional'),
        ('client', 'Client'),
    )
    
    # Additional fields
    username = None 
    email = models.EmailField(unique=True)
    role = models.CharField(max_length=12, choices=ROLE_CHOICES, default='client')
    is_blocked = models.BooleanField(default=False)
    name = models.CharField(max_length=100, default="Unnamed User")
    objects = CustomUserManager()
    is_verified = models.BooleanField(default=False)  # Add email verification flag
    otp = models.CharField(max_length=6, blank=True, null=True)  # OTP field
    otp_created_at = models.DateTimeField(blank=True, null=True)  # OTP timestamp

    groups = models.ManyToManyField(
        "auth.Group",
        related_name="customuser_set",
        blank=True
    )
    user_permissions = models.ManyToManyField(
        "auth.Permission",
        related_name="customuser_permissions_set",
        blank=True
    )
    
    # Use email instead of username for authentication
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name']  
    
    def __str__(self):
        return self.email

# accounts/models.py
class ProfessionalProfile(models.Model):
    AVAILABILITY_CHOICES = [
        ('Available', 'Available'),
        ('Busy', 'Busy'),
        ('Not Taking Work', 'Not Taking Work'),
    ]
    VERIFY_STATUS_CHOICES = [
        ('Pending', 'Pending'),
        ('Verified', 'Verified'),
        ('Not Verified', 'Not Verified'),
    ]

    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, primary_key=True)
    bio = models.TextField(blank=True)
    skills = models.JSONField(default=list, blank=True)
    experience_years = models.PositiveIntegerField(default=0)
    availability_status = models.CharField(max_length=15, choices=AVAILABILITY_CHOICES, default='Available')
    portfolio_links = models.JSONField(default=list, blank=True)
    verify_doc = CloudinaryField(
        'verify_doc',
        null=True,
        blank=True,
        resource_type='auto',  # Supports images and documents
        folder='verification_documents/',  # Organizes files in Cloudinary
        help_text='Upload verification document (ID, degree, certificate, etc.)'
    )
    verify_status = models.CharField(max_length=15, choices=VERIFY_STATUS_CHOICES, default='Pending')
    avg_rating = models.FloatField(default=0.0)
    denial_reason = models.TextField(blank=True, null=True) 
    def get_verify_doc_url(self):
        """Get the full URL of the verification document if it exists"""
        if self.verify_doc:
            return self.verify_doc.url
        return None

    def get_verify_doc_public_id(self):
        """Get the Cloudinary public ID of the verification document"""
        if self.verify_doc:
            return self.verify_doc.public_id
        return None

    def delete_verify_doc(self):
        """Delete the verification document from Cloudinary"""
        if self.verify_doc:
            try:
                import cloudinary.uploader
                public_id = self.verify_doc.public_id
                cloudinary.uploader.destroy(public_id, resource_type='auto')
                self.verify_doc = None
                self.save()
                logger.info(f"Deleted verification document for user {self.user.id}")
                return True
            except Exception as e:
                logger.error(f"Failed to delete verification document: {e}")
                return False
        return False
    def update_avg_rating(self):
        jobs = Job.objects.filter(
            applications__professional_id=self.user,
            applications__status='Completed',  # Fixed to 'Completed'
            status='Completed',
            rating__isnull=False
        )
        print(f"Debug: Found {jobs.count()} rated jobs for {self.user.email}: {jobs.values('job_id', 'rating')}")  # Debug
        if jobs.exists():
            avg_rating = jobs.aggregate(models.Avg('rating'))['rating__avg']
            self.avg_rating = round(avg_rating, 1)
            self.save()
            print(f"Debug: Updated avg_rating to {self.avg_rating} for {self.user.email}")  # Debug
        else:
            self.avg_rating = 0.0
            self.save()
            print(f"Debug: No rated jobs, avg_rating set to {self.avg_rating} for {self.user.email}")  # Debug

    def __str__(self):
        return f"{self.user.name}'s Professional Profile"
class Job(models.Model):
    STATUS_CHOICES = [
        ('Open', 'Open'),
        ('Assigned', 'Assigned'),
        ('Completed', 'Completed'),
        ('Closed', 'Closed'),
    ]
     # NEW: Cloudinary document field
    document = CloudinaryField(
        'document',
        null=True,
        blank=True,
        resource_type='auto',  # Supports images, videos, and raw files (PDFs, docs, etc.)
        folder='job_documents/',
        transformation=[],  # Organizes files in Cloudinary
        help_text='Upload project documents, requirements, or reference files'
    )

    professional_id = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,  # Use SET_NULL to avoid deleting jobs when a professional is deleted
        related_name='assigned_jobs',
        null=True,
        blank=True
    )
    job_id = models.AutoField(primary_key=True)
    client_id = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='jobs'
    )
    title = models.CharField(max_length=255)
    description = models.TextField()
    budget = models.DecimalField(max_digits=10, decimal_places=2)
    deadline = models.DateField()
    status = models.CharField(
        max_length=10,
        choices=STATUS_CHOICES,
        default='Open'
    )

    created_at = models.DateTimeField(default=now)
    advance_payment = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    rating = models.IntegerField(
        null=True,
        blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(5)]
    )
    review = models.TextField(null=True, blank=True)

    def __str__(self):
        return self.title
   

    def get_document_url(self):
        """Get the full URL of the uploaded document"""
        if self.document:
            return self.document.url
        return None

    def get_document_public_id(self):
        """Get the Cloudinary public ID of the document"""
        if self.document:
            return self.document.public_id
        return None

# Step 2: Update your serializer method in account/serializers.py
# In your JobSerializer class, update the get_document_url method:

    def get_document_url(self, obj):
        """Return the full URL of the document if it exists"""
        if hasattr(obj, 'document') and obj.document:
            return obj.document.url
        return None

    # Step 3: Alternative - Temporary fix for existing serializer
    # If you want to avoid the error immediately while testing, you can update the serializer method to:

    def get_document_url(self, obj):
        """Return the full URL of the document if it exists - with error handling"""
        try:
            if hasattr(obj, 'document') and obj.document:
                return obj.document.url
            elif hasattr(obj, 'get_document_url'):
                return obj.get_document_url()
            return None
        except AttributeError:
            return None
# accounts/models.py
# accounts/models.py
class JobApplication(models.Model):
    STATUS_CHOICES = [
        ('Applied', 'Applied'),
        ('Accepted', 'Accepted'),
        ('Rejected', 'Rejected'),
        ('Completed', 'Completed'),  # Added
        ('Cancelled', 'Cancelled'),  # Added
    ]

    application_id = models.AutoField(primary_key=True)
    job_id = models.ForeignKey(
        'Job',
        on_delete=models.CASCADE,
        related_name='applications'
    )
    professional_id = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='job_applications'
    )
    status = models.CharField(
        max_length=10,
        choices=STATUS_CHOICES,
        default='Applied'
    )
    applied_at = models.DateTimeField(default=now)

    def __str__(self):
        return f"Application {self.application_id} for Job {self.job_id} by {self.professional_id}"
class Payment(models.Model):
    PAYMENT_TYPE_CHOICES = [
        ('initial', 'Initial Payment'),
        ('remaining', 'Remaining Payment'),
    ]
    
    job_application = models.ForeignKey(
        'JobApplication',
        on_delete=models.CASCADE,
        related_name='payments'
    )
    payment_type = models.CharField(max_length=20, choices=PAYMENT_TYPE_CHOICES)
    razorpay_order_id = models.CharField(max_length=100)
    razorpay_payment_id = models.CharField(max_length=100, null=True, blank=True)
    razorpay_signature = models.CharField(max_length=255, null=True, blank=True)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    status = models.CharField(
        max_length=20,
        choices=[('created', 'Created'), ('completed', 'Completed'), ('failed', 'Failed')],
        default='created'
    )
    created_at = models.DateTimeField(default=now)

    def __str__(self):
        return f"{self.payment_type} {self.razorpay_order_id} for Application {self.job_application.application_id}"
class PaymentRequest(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]

    request_id = models.AutoField(primary_key=True)  # INT (PK)
    payment = models.OneToOneField(
        Payment,
        on_delete=models.CASCADE,
        related_name='payment_request'
    )  # INT (FK) referencing Payment(payment_id)
    client = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='payment_requests'
    )  # INT (FK) referencing CustomUser(id)
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='pending'
    )  # ENUM
    created_at = models.DateTimeField(default=now)  # DATETIME

    def __str__(self):
        return f"Payment Request {self.request_id} for {self.payment} by {self.client.email}"
class Complaint(models.Model):
    STATUS_CHOICES = (
        ('PENDING', 'Pending'),
        ('IN_PROGRESS', 'In Progress'),
        ('AWAITING_USER_RESPONSE', 'Awaiting User Response'),
        ('NEEDS_FURTHER_ACTION', 'Needs Further Action'),
        ('RESOLVED', 'Resolved'),
        ('CLOSED', 'Closed'),
    )
    # NEW FIELDS for enhanced functionality
    admin_response = models.TextField(blank=True, null=True)
    responded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True, 
        related_name='responded_complaints'
    )
    response_date = models.DateTimeField(null=True, blank=True)
    
    # Client feedback fields
    client_feedback = models.TextField(blank=True, null=True)
    resolution_rating = models.PositiveSmallIntegerField(
        null=True, 
        blank=True,
        validators=[MinValueValidator(1), MaxValueValidator(5)]
    )
    feedback_date = models.DateTimeField(null=True, blank=True)
    
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='complaints')
    description = models.TextField()
    status = models.CharField(max_length=30, choices=STATUS_CHOICES, default='PENDING')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    @property
    def can_mark_resolved(self):
        return self.status == 'AWAITING_USER_RESPONSE'
    
    @property
    def responded_by_name(self):
        return self.responded_by.name if self.responded_by else None

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Complaint {self.id} by {self.user.email}"

    def user_role(self):
        return self.user.role if self.user.role else 'Unknown'
class Conversation(models.Model):
    job = models.OneToOneField(Job, on_delete=models.CASCADE, related_name='conversation')
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Conversation for {self.job.title}"


class Message(models.Model):
    conversation = models.ForeignKey(Conversation, on_delete=models.CASCADE, related_name='messages')
    sender = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='sent_messages')
    content = models.TextField(blank=True, null=True)  # Allow blank for file-only messages
    file = models.FileField(
        upload_to='%Y/%m/%d/', 
        storage=LocalFileStorage(),
        blank=True, 
        null=True
    )  # Store files in 'chat_files/' directory
    file_type = models.CharField(max_length=20, blank=True, null=True)  # E.g., 'image', 'document', 'text'
    created_at = models.DateTimeField(auto_now_add=True)
    is_read = models.BooleanField(default=False)
    
   
    
    # Add this new field to store the absolute URL
    file_absolute_url = models.URLField(max_length=500, null=True, blank=True)
    class Meta:
        ordering = ['created_at']
    
    def __str__(self):
        return f"Message from {self.sender.name} at {self.created_at}"

    def save(self, *args, **kwargs):
        # Auto-generate absolute URL when file is saved
        super().save(*args, **kwargs)
        if self.file and not self.file_absolute_url:
            # This will be set by the view after getting the request context
            pass
