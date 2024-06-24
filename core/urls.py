from django.urls import path
from .views import UserSignupView, LogoutView, VerifyEmailView, LoginView, FileUploadView, FileListView, FileDownloadView


urlpatterns = [
    path('signup/', UserSignupView.as_view(), name='signup'),
    path('verify-email/<str:token>/', VerifyEmailView.as_view(), name='verify-email'),
    path('login/', LoginView.as_view(), name='login'),
    path('upload/', FileUploadView.as_view(), name='file-upload'),
    path('files/', FileListView.as_view(), name='files'),
    path('download/<int:pk>/', FileDownloadView.as_view(), name='download'),
    path('logout/', LogoutView.as_view(), name='logout'),
]
