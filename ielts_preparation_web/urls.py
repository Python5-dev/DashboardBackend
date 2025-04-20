from django.contrib import admin
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from rest_framework_simplejwt.views import TokenRefreshView
from app.views import VerifyOTP, Register, Login, ResetPassword, Dashboard, DeleteUser, CheckAndUpdateProfile, DeleteProfile, AddBook, RetrieveBook, EditBook, DeleteBook, AddNotification, SocialLogin, AddLogActivities, RetrieveLogActivities

urlpatterns = [
    path('admin/', admin.site.urls),
    path('verify-otp/', VerifyOTP.as_view()),
    path('register/', Register.as_view()),
    path('login/', Login.as_view()),
    path('log-activities/', AddLogActivities.as_view()),
    path('retrieve-log-activities/', RetrieveLogActivities.as_view()),
    path('api/social-login/', SocialLogin.as_view(), name='social_login'),
    path('reset-password/<str:username>/', ResetPassword.as_view()),
    path('api/token/refresh/', TokenRefreshView.as_view()),
    path('dashboard/', Dashboard.as_view()),
    path('dashboard/user/delete/<str:username>/', DeleteUser.as_view()),
    path('check-and-update-profile/<str:username>/', CheckAndUpdateProfile.as_view()),
    path('profile/delete/<str:username>/', DeleteProfile.as_view()),
    path('add-book/', AddBook.as_view()),
    path('retrieve-book/', RetrieveBook.as_view()),
    path('edit-book/<str:title>/', EditBook.as_view()),
    path('delete-book/<str:title>/', DeleteBook.as_view()),
    path('add-notification/', AddNotification.as_view())
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)