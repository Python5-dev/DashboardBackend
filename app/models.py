from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.utils.translation import gettext_lazy as _

class CustomUser(AbstractUser):
    # yahan apni extra field add karo, misaal ke taur par:
    status = models.BooleanField(default=False)

    groups = models.ManyToManyField(
        Group,
        verbose_name=_('groups'),
        blank=True,
        related_name='customuser_groups',       # unique related_name
        related_query_name='customuser',
    )
    user_permissions = models.ManyToManyField(
        Permission,
        verbose_name=_('user permissions'),
        blank=True,
        related_name='customuser_user_permissions',  # unique related_name
        related_query_name='customuser',
    )
    

    def __str__(self):
        return self.username

class Profile(models.Model):
    username = models.CharField(max_length=100)
    image= models.ImageField(upload_to='images', null=True, blank=True, default="default_profile.png")

    def __str__(self):
        return self.username

class Book(models.Model):
    title = models.CharField(max_length=100)
    type = models.CharField(max_length=100,  default='Book Type')
    file = models.FileField(upload_to='books/', default="default_profile.png")

    def __str__(self):
        return self.title

class Pdf(models.Model):
    title = models.CharField(max_length=100)
    type = models.CharField(max_length=100,  default='Book Type')
    file = models.FileField(upload_to='books/', default="default_profile.png")

    def __str__(self):
        return self.title

class Slide(models.Model):
    title = models.CharField(max_length=100)
    type = models.CharField(max_length=100,  default='Book Type')
    file = models.FileField(upload_to='books/', default="default_profile.png")

    def __str__(self):
        return self.title

class PastPaper(models.Model):
    title = models.CharField(max_length=100)
    type = models.CharField(max_length=100,  default='Book Type')
    file = models.FileField(upload_to='books/', default="default_profile.png")

    def __str__(self):
        return self.title
    
class Notification(models.Model):
    notification = models.CharField(max_length=100)

class LogActivities(models.Model):
    username_or_email = models.CharField(max_length=100, default='No User')
    activities = models.JSONField(default=list)

    def __str__(self):
        return self.username_or_email