from rest_framework.views import APIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from .serializers import UserSerializer, ProfileSerializer
from django.db import IntegrityError
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken, UntypedToken
from.email import send_reset_password_email
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from datetime import timedelta
from rest_framework.test import APIRequestFactory
from rest_framework_simplejwt.exceptions import TokenError
from .models import Profile
from rest_framework.generics import CreateAPIView, RetrieveAPIView, UpdateAPIView, DestroyAPIView

class Register(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')
        confirm_password = request.data.get('confirmPassword')

        if password != confirm_password:
            return Response({'error': 'Password and Confirm Password does not match'}, status=status.HTTP_400_BAD_REQUEST)
        
        if User.objects.filter(username=username).exists():
            return Response({'error': 'A user with this username already exists.'}, status=status.HTTP_400_BAD_REQUEST)
            
        if User.objects.filter(email=email).exists():
            return Response({'error': 'A user with this email already exists.'}, status=status.HTTP_400_BAD_REQUEST)
        
        serializer = UserSerializer(data=request.data)
        
        if serializer.is_valid():
            try:
                serializer.save()
                return Response({'message': 'User registered successfully.'}, status=status.HTTP_201_CREATED)
            except IntegrityError:
                return Response({'error': 'Database error occurred during registration.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class Login(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username_or_email = request.data.get('username_or_email')
        password = request.data.get('password')

        user = authenticate(request, username=username_or_email, password=password)

        if user is not None:
            # Generate JWT token
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'message': 'Login successful.'
            }, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)
        
class ForgotPassword(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        send_reset_password_email(email, user)
        return Response({'message': 'Password Reset Email Sent Successfully',}, status=status.HTTP_200_OK)

class ResetPassword(APIView):
    permission_classes = [AllowAny]

    def check_token_expiration(self, user, token):
        token_generator = PasswordResetTokenGenerator()
        if token_generator.check_token(user, token):
            expiration_time = timezone.now() - timedelta(minutes=5)
            if token_generator.timestamp < expiration_time:
                return False
            return True
        return False
    
    def update(self, request):
        uidb64 = request.data.get('uid')
        token = request.data.get('token')
        new_password = request.data.get('newPassword')
        confirm_password = request.data.get('confirmPassword')

        if new_password != confirm_password:
            return Response({'error': 'New Password and Confirm Password does not match'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = User.objects.get(pk=uid)
            if self.check_token(user, token):
                user.password = make_password(new_password)
                user.save()
                return Response({"message": "Password reset successful."}, status=status.HTTP_200_OK)
            else:
                return Response({"error": "Invalid or expired token."}, status=status.HTTP_400_BAD_REQUEST)
        except (User.DoesNotExist, ValueError, TypeError):
            return Response({"error": "Invalid user."}, status=status.HTTP_400_BAD_REQUEST)

class Dashboard(APIView):
    def post(self, request):
        jwt_token = request.headers.get('Authorization')

        if not jwt_token or not jwt_token.startswith("Bearer "):
            return Response({'error': 'Invalid or missing Authorization header.'}, status=status.HTTP_400_BAD_REQUEST)
        jwt_token = jwt_token.split(" ")[1]

        try:
            # verify the JWT token
            verified_token = UntypedToken(jwt_token)
            user_id = verified_token.payload.get('user_id')
            user = User.objects.get(id=user_id)

            if user.is_staff:
                users = User.objects.all()
                serializer = UserSerializer(users, many=True)
                return Response({
                    'access': jwt_token,
                    'users': serializer.data
                }, status=status.HTTP_200_OK)

            return self.get_user_profile(user)

        except TokenError as e:
            return self.handle_token_error(e, request)

    def get_user_profile(self, user):
        factory = APIRequestFactory()
        drf_request = factory.get(f'/profile/{user.username}/')
        view = RetrieveProfile.as_view()
        return view(drf_request, username=user.username)
    
    # Generate Refresh Token if access token has expired
    def handle_token_error(self, error, request):
        if str(error) == "Token is invalid or expired":
            refresh_token = request.data.get('refresh')
            if not refresh_token:
                return Response({'error': 'Refresh token required for reauthentication.'}, status=status.HTTP_400_BAD_REQUEST)

            try:
                refresh = RefreshToken(refresh_token)
                new_access_token = str(refresh.access_token)
                return Response({'message': 'Token refreshed successfully.', 'access': new_access_token}, status=status.HTTP_200_OK)

            except TokenError as e:
                return Response({'error': 'Refresh token invalid or expired.', 'details': str(e)}, status=status.HTTP_401_UNAUTHORIZED)

        return Response({'error': 'Invalid token.', 'details': str(error)}, status=status.HTTP_401_UNAUTHORIZED)

class DeleteUser(DestroyAPIView):
    queryset = User.objects.all()
    lookup_field = 'username'

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response({'message': 'User Deleted Successfully'}, status=status.HTTP_200_OK)

class RetrieveProfile(RetrieveAPIView): 
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer
    lookup_field = 'username'

class UpdateProfile(UpdateAPIView):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer
    lookup_field = 'username'

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_update(instance)
        return Response({'message': 'Profile Updated Successfully'}, status=status.HTTP_200_OK)

class DeleteProfile(DestroyAPIView):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer
    lookup_field = 'username'

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response({'message': 'Profile Deleted Successfully'}, status=status.HTTP_200_OK)