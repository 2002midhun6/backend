from django.core.mail import send_mail
from django.conf import settings
import random
from django.utils import timezone

def send_otp_email(user):
    subject = 'Your OTP for Account Verification'
    
    message = f'''Dear {user.username or "User"},

Thank you for signing up!

Your One-Time Password (OTP) for account verification is: {user.otp}

This OTP is valid for 10 minutes and can only be used once.

For your security:
- Do not share this OTP with anyone
- We will never ask for your OTP via phone or email
- If you didn't request this verification, please ignore this email

If you need assistance, please contact our support team.

Best regards,
{settings.SITE_NAME or "The Team"}

---
This is an automated message, please do not reply to this email.
'''
    
    from_email = settings.EMAIL_HOST_USER
    recipient_list = [user.email]
    
    send_mail(subject, message, from_email, recipient_list)