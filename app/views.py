from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAdminUser, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.models import User
from .serializers import UserSerializer, ProfileSerializer, BookSerializer, NotificationSerializer, LogActivitiesSerializer
from django.db import IntegrityError
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken, UntypedToken
from .email import send_reset_password_email
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth.hashers import make_password
from django.utils import timezone
from datetime import timedelta
from rest_framework.test import APIRequestFactory
from rest_framework_simplejwt.exceptions import TokenError
from .models import Profile, Book, Notification, LogActivities
from rest_framework.generics import CreateAPIView, ListAPIView, RetrieveAPIView, UpdateAPIView, DestroyAPIView
from django.core.cache import cache
from django.core.mail import send_mail
from django.conf import settings
import random
from rest_framework.test import force_authenticate
import requests;
from jose import jwt;

AUTH0_DOMAIN = 'dev-u2q8ttozips0ckyh.us.auth0.com'
API_IDENTIFIER = 'https://dev-u2q8ttozips0ckyh.us.auth0.com/api/v2/'
ALGORITHMS = ['RS256']

class VerifyOTP(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        otp = request.data.get('otp')

        stored_otp = cache.get(email)

        if not stored_otp:
            return Response({'error': 'OTP expired or not found'}, status=status.HTTP_400_BAD_REQUEST)

        if otp != str(stored_otp):
            return Response({'error': 'Incorrect OTP'}, status=status.HTTP_400_BAD_REQUEST)

        username = request.data.get('username')
        password = request.data.get('password')

        User.objects.create_user(username=username, email=email, password=password)

        cache.delete(email)

        return Response({'message': 'User registered successfully.'}, status=status.HTTP_201_CREATED)

class Register(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')
        confirm_password = request.data.get('confirmPassword')

        # Check if passwords match
        if password != confirm_password:
            return Response({'error': 'Password and Confirm Password do not match'}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(username=username).exists():
            return Response({'error': 'A user with this username already exists.'}, status=status.HTTP_400_BAD_REQUEST)

        if User.objects.filter(email=email).exists():
            return Response({'error': 'A user with this email already exists.'}, status=status.HTTP_400_BAD_REQUEST)

        # Generate OTP and store it in cache for 10 minutes (600 seconds)
        otp = random.randint(10000000, 99999999)
        cache.set(email, otp, timeout=600)

        try:
            send_mail(
                'Verify Otp',
                f'Your OTP is {otp}',
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
            )
        except Exception as e:
            return Response({'error': f'Error sending OTP: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({'message': 'User registration initiated, OTP sent to your email.'}, status=status.HTTP_200_OK)


class Login(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username_or_email = request.data.get('username_or_email')
        password = request.data.get('password')

        user = authenticate(request, username=username_or_email, password=password)

        if user is not None:
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'message': 'Login successful.'
            }, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid credentials.'}, status=status.HTTP_401_UNAUTHORIZED)
        
class SocialLogin(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        token = request.data.get('access_token')
        if not token:
            return Response({'error': 'Access token is required'}, status=status.HTTP_400_BAD_REQUEST)

        # Get the public key
        jwks_url = f'https://{AUTH0_DOMAIN}/.well-known/jwks.json'
        jwks = requests.get(jwks_url).json()
        unverified_header = jwt.get_unverified_header(token)
        rsa_key = {}
        for key in jwks['keys']:
            if key['kid'] == unverified_header['kid']:
                rsa_key = {
                    'kty': key['kty'],
                    'kid': key['kid'],
                    'use': key['use'],
                    'n': key['n'],
                    'e': key['e']
                }

        if rsa_key:
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=ALGORITHMS,
                    audience=API_IDENTIFIER,
                    issuer=f'https://{AUTH0_DOMAIN}/'
                )
            except jwt.ExpiredSignatureError:
                return Response({'error': 'Token expired'}, status=status.HTTP_401_UNAUTHORIZED)
            except jwt.JWTClaimsError:
                return Response({'error': 'Incorrect claims'}, status=status.HTTP_401_UNAUTHORIZED)
            except Exception:
                return Response({'error': 'Unable to parse authentication token.'}, status=status.HTTP_400_BAD_REQUEST)

            email = payload.get('email')
            if not email:
                return Response({'error': 'Email not provided'}, status=status.HTTP_400_BAD_REQUEST)

            user, created = User.objects.get_or_create(username=email, defaults={'email': email})
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'message': 'Login successful.'
            }, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Unable to find appropriate key'}, status=status.HTTP_400_BAD_REQUEST)

class ResetPassword(APIView):
    permission_classes = [AllowAny]

    def post(self, request, username, *args, **kwargs):
        new_password = request.data.get('password')
        print(new_password)

        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            return Response(
                {"error": f"User with username '{username}' does not exist."},
                status=status.HTTP_404_NOT_FOUND
            )

        user.set_password(new_password)
        user.save()

        return Response(
            {"message": "Password changed successfully."},
            status=status.HTTP_200_OK
        )

class Dashboard(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        jwt_token = request.headers.get('authorization')

        if not jwt_token or not jwt_token.startswith("Bearer "):
            return Response({'error': 'Invalid or missing Authorization header.'}, status=status.HTTP_400_BAD_REQUEST)
        jwt_token = jwt_token.split(" ")[1]

        try:
            verified_token = UntypedToken(jwt_token)
            user_id = verified_token.payload.get('user_id')
            user = User.objects.get(id=user_id)

            if user.is_staff:
                users = User.objects.all()
                serializer = UserSerializer(users, many=True)
                return Response({
                    'users': serializer.data
                }, status=status.HTTP_200_OK)

            response = self.get_user_profile(user)
        
            if response.status_code == 200:
                return Response({"Response": response.data, "username": user.username, "email": user.email, "status": response.status_code}, status=status.HTTP_200_OK)
    
            return Response({"error": "Profile not found or incomplete data", "username": user.username, "email": user.email, "status": response.status_code})

        except TokenError as e:
            return self.handle_token_error(e, request)

    def get_user_profile(self, user):
        factory = APIRequestFactory()
        drf_request = factory.get(f'/profile/{user.username}/')
        force_authenticate(drf_request, user=user)
        view = RetrieveProfile.as_view()
        return view(drf_request, username=user.username)
    
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

class CreateProfile(CreateAPIView):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer

class RetrieveProfile(RetrieveAPIView): 
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer
    lookup_field = 'username'

class UpdateProfile(UpdateAPIView):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer
    lookup_field = 'username'

    def update(self, request, *args, **kwargs):
        # Profile instance ko dhoondhna
        instance = self.get_object()

        # Serializer ko update karte hain, aur partial=True isliye diya hai taake sirf request mein diye gaye fields update ho
        serializer = self.get_serializer(instance, data=request.data, partial=True)

        # Agar serializer valid hai, toh update perform karo
        if serializer.is_valid():
            serializer.save()  # Data ko save karna

            return Response({'message': 'Profile Updated Successfully'}, status=status.HTTP_200_OK)
        else:
            # Agar validation fail hoti hai, toh error return karo
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class DeleteProfile(DestroyAPIView):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer
    lookup_field = 'username'

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response({'message': 'Profile Deleted Successfully'}, status=status.HTTP_200_OK)

class CheckAndUpdateProfile(APIView):
    def post(self, request, username):
        profile = Profile.objects.filter(username=username).first()

        try:
            if profile:
                serializer = ProfileSerializer(profile, data=request.data, partial=True)
                if serializer.is_valid():
                    serializer.save()
                    return Response({"message": "Profile updated successfully."}, status=status.HTTP_200_OK)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            else:
                serializer = ProfileSerializer(data=request.data)
                if serializer.is_valid():
                    serializer.save()
                    return Response({"message": "Profile created successfully."}, status=status.HTTP_201_CREATED)
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class AddBook(CreateAPIView):
    queryset = Book.objects.all()
    serializer_class = BookSerializer
    
class RetrieveBook(ListAPIView):
    serializer_class = BookSerializer

    def get_queryset(self):
        book_type = self.request.query_params.get('type', None)
        if book_type:
            return Book.objects.filter(type=book_type)
        return Book.objects.all()

class EditBook(UpdateAPIView):
    queryset = Book.objects.all()
    serializer_class = BookSerializer
    lookup_field = 'title'

class DeleteBook(DestroyAPIView):
    queryset = Book.objects.all()
    serializer_class = BookSerializer
    lookup_field = 'title'

class AddNotification(CreateAPIView):
    queryset = Notification.objects.all()
    serializer_class = NotificationSerializer

class AddLogActivities(CreateAPIView):
    queryset = LogActivities.objects.all()
    serializer_class = LogActivitiesSerializer

class RetrieveLogActivities(ListAPIView):
    queryset = LogActivities.objects.all()
    serializer_class = LogActivitiesSerializer
