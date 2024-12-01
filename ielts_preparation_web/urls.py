from django.contrib import admin
from django.urls import path
from app.views import Register, Login, ForgotPassword, ResetPassword, Dashboard, DeleteUser, UpdateProfile, DeleteProfile

urlpatterns = [
    path('admin/', admin.site.urls),
    path('register/', Register.as_view()),
    path('login/', Login.as_view()),
    path('forgot-password/', ForgotPassword.as_view()),
    path('reset-password/', ResetPassword.as_view()),
    path('dashboard/', Dashboard.as_view()),
    path('dashboard/user/delete/<str:username>/', DeleteUser.as_view()),
    path('profile/update/<str:username>/', UpdateProfile.as_view()),
    path('profile/delete/<str:username>/', DeleteProfile.as_view())
]
