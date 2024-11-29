from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.core.mail import send_mail
from django.conf import settings

def send_reset_password_email(email, user):
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token_generator = PasswordResetTokenGenerator()
    token = token_generator.make_token(user)
    link = f'http://127.0.0.1:5173/reset-password/{uid}/{token}/'
    subject = 'Reset Password Request'
    message = f"""
    You are receiving this email because you requested a password reset for your user account at IELTS Preparation Web.
            
    Please go to the following page and choose a new password:
            
    {link}

    For your security, this link will expire in 5 minutes, so please make sure to change your password within this time frame.

    Thanks for using our site!"""
    email_from = settings.EMAIL_HOST_USER
    send_mail(subject, message, email_from, [email])
