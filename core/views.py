from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import User, File
from .serializers import UserSerializer, FileSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.urls import reverse
from django.conf import settings
import hashlib
import base64
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import MultiPartParser, FormParser

class UserSignupView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def perform_create(self, serializer):
        user = serializer.save()
        user.set_password(serializer.validated_data['password'])
        user.is_active = False  # User is inactive until email is verified
        user.save()

        # Send verification email
        token = urlsafe_base64_encode(force_bytes(user.pk))
        url = reverse('verify-email', kwargs={'token': token})
        verify_url = f"{settings.FRONTEND_URL}{url}"
        print("Click this url to verify email : ", verify_url)
        try:
            send_mail(
                'Verify your email',
                f'Click here to verify your email: {verify_url}',
                settings.DEFAULT_FROM_EMAIL,
                [user.email]
            )
        except Exception as e:
            print(f'"Click this url to verify email : ", {verify_url}'*5)


        return Response({"message": "User created successfully. Please check your email for verification."}, status=status.HTTP_201_CREATED)

class VerifyEmailView(APIView):
    def get(self, request, token):
        try:
            uid = force_str(urlsafe_base64_decode(token))
            user = User.objects.get(pk=uid)
            user.is_active = True
            user.save()
            return Response({"message": "Email verified successfully"}, status=status.HTTP_200_OK)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"message": "Invalid token"}, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = User.objects.filter(username=username).first()
        if user and user.check_password(password):
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            })
        return Response({"message": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)

class FileUploadView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request, *args, **kwargs):
        file = request.FILES.get('file')
        if file and file.name.split('.')[-1] in ['pptx', 'docx', 'xlsx']:
            File.objects.create(user=request.user, file=file)
            return Response({"message": "File uploaded successfully"}, status=status.HTTP_201_CREATED)
        return Response({"error": "Invalid file type"}, status=status.HTTP_400_BAD_REQUEST)

class FileListView(generics.ListAPIView):
    serializer_class = FileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return File.objects.all()

class FileDownloadView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, pk):
        file = File.objects.filter(pk=pk).first()
        if file and request.user.user_type == 2:
            download_url = self.generate_secure_url(file.file.name)
            return Response({"download-link": download_url, "message": "success"}, status=status.HTTP_200_OK)
        return Response({"message": "Access denied"}, status=status.HTTP_403_FORBIDDEN)

    def generate_secure_url(self, filename):
        hash_object = hashlib.sha256(filename.encode())
        secure_url = base64.urlsafe_b64encode(hash_object.digest()).decode('utf-8')
        return f"{settings.FRONTEND_URL}/download/{secure_url}"

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.data["refresh"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)