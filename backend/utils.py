from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone

def send_otp_email(user, purpose='verification'):
    """
    Send OTP email for different purposes
    Args:
        user: User object
        purpose: 'verification' or 'password_reset'
    """
    
    if purpose == 'verification':
        subject = 'Verify Your Email - Account Activation'
        greeting = f'''Hello {user.name or user.email},

Welcome to JobSeeker! We're thrilled to have you join our platform.

To activate your account and get started, please verify your email address using the OTP below:'''
        
        action_text = "Please enter this code to complete your registration and activate your account."
        
    else:  # password_reset
        subject = 'Password Reset Request - Security Alert'
        greeting = f'''Hello {user.name or user.email},

We received a request to reset your password for your JobSeeker account.'''
        
        action_text = "Please enter this code to reset your password and regain access to your account."
    
    message = f'''{greeting}

Your One-Time Password (OTP) is:

    ***** {user.otp} *****

{action_text}

This OTP is valid for 10 minutes and can only be used once.

IMPORTANT SECURITY INFORMATION:
- Do NOT share this OTP with anyone, including our support team
- We will NEVER call or email asking for your OTP
- This code can only be used once
- If you didn't request this, please ignore this email - your account remains secure

Need help? Contact us at support@jobseeker.com

Best regards,
The JobSeeker Team

---
This is an automated message. Please do not reply to this email.
© {timezone.now().year} JobSeeker. All rights reserved.
'''
    
    from_email = settings.EMAIL_HOST_USER
    recipient_list = [user.email]
    
    send_mail(subject, message, from_email, recipient_list)