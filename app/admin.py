from django.contrib import admin
from .models import Profile

@admin.register(Profile)
class RegisterAdmin(admin.ModelAdmin):
    list_display = ['username', 'image']