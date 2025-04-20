from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Profile, Book, Pdf, Slide, PastPaper, Notification, LogActivities
from datetime import datetime

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'email', 'password']
    
    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password']
        )
        return user
    
class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        fields = ['username', 'image']

        def validate_user(self, value):
            if Profile.objects.filter(user=value).exists():
                raise serializers.ValidationError("A profile for this user already exists.")
            return value
        
        def get_profile_image(self, obj):
            request = self.context.get("request")
            if obj.profile_image:
                return request.build_absolute_uri(obj.profile_image.url)
            return None
        
class BookSerializer(serializers.ModelSerializer):
    class Meta:
        model = Book
        fields = '__all__'

class PdfSerializer(serializers.ModelSerializer):
    class Meta:
        model = Pdf
        fields = '__all__'

class SlideSerializer(serializers.ModelSerializer):
    class Meta:
        model = Slide
        fields = '__all__'

class PastPaperSerializer(serializers.ModelSerializer):
    class Meta:
        model = PastPaper
        fields = '__all__'

class NotificationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Notification
        fields = '__all__'

class LogActivitiesSerializer(serializers.ModelSerializer):
    activities = serializers.JSONField()  # ya DictField if you're using dicts

    class Meta:
        model = LogActivities
        fields = ['username_or_email', 'activities']

    def create(self, validated_data):
        username_or_email = validated_data.get('username_or_email')
        new_activity = validated_data.get('activities')  # {"login": "..."} ya {"logout": "..."}

        log_activity, created = LogActivities.objects.get_or_create(username_or_email=username_or_email)

        if log_activity.activities is None:
            log_activity.activities = []

        if 'login' in new_activity:
            log_activity.activities.append({'login': new_activity['login']})

        elif 'logout' in new_activity:
            if log_activity.activities and 'logout' not in log_activity.activities[-1]:
                log_activity.activities[-1]['logout'] = new_activity['logout']
            else:
                log_activity.activities.append({'logout': new_activity['logout']})

        log_activity.save()
        return log_activity