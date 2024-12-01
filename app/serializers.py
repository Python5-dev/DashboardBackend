from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Profile
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