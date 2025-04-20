from django.contrib import admin
from .models import Profile, Book, Pdf, Slide, PastPaper, Notification, LogActivities, CustomUser
from django.contrib.auth.admin import UserAdmin

@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    fieldsets = UserAdmin.fieldsets + (
        ('Extra Info', {'fields': ('bio', 'birth_date')}),
    )

@admin.register(Profile)
class RegisterAdmin(admin.ModelAdmin):
    list_display = ['username', 'image']

@admin.register(Book)
class RegisterAdmin(admin.ModelAdmin):
    list_display = ['title','type', 'file']

@admin.register(Pdf)
class RegisterAdmin(admin.ModelAdmin):
    list_display = ['title', 'type', 'file']

@admin.register(Slide)
class RegisterAdmin(admin.ModelAdmin):
    list_display = ['title', 'type', 'file']

@admin.register(PastPaper)
class RegisterAdmin(admin.ModelAdmin):
    list_display = ['title', 'type', 'file']

@admin.register(Notification)
class RegisterAdmin(admin.ModelAdmin):
    list_display = ['notification']

@admin.register(LogActivities)
class RegisterAdmin(admin.ModelAdmin):
    list_display = ['username_or_email', 'activities']