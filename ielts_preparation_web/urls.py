from django.contrib import admin
from django.urls import path
from app.views import Register, Login, ForgotPassword, ResetPassword

urlpatterns = [
    path('admin/', admin.site.urls),
    path('register/', Register.as_view()),
    path('login/', Login.as_view()),
    path('forgot-password/', ForgotPassword.as_view()),
    path('reset-password/', ResetPassword.as_view())
]
