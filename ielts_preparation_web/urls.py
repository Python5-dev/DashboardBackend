from django.contrib import admin
from django.urls import path
from app.views import Register

urlpatterns = [
    path('admin/', admin.site.urls),
    path('register/', Register.as_view()),
]
