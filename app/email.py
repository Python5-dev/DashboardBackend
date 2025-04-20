import random
from django.core.mail import send_mail
from django.conf import settings

def send_reset_password_email(email):
    otp = random.randint(1000, 9999)
    subject = 'Email Verification',
    message = f'Your otp is {otp}'
    email_from = settings.EMAIL_HOST_USER
    send_mail(subject, message, email_from, [email])
    return otp