from django.core.mail import send_mail
from django.conf import settings
import random
from django.utils import timezone

def send_otp_email(user):
    subject = 'Your OTP for verification'
    
    message = f'Your OTP for account verification is: {user.otp}'
    from_email = settings.EMAIL_HOST_USER
    recipient_list = [user.email]
    
    # Send only one email
    send_mail(subject, message, from_email, recipient_list)