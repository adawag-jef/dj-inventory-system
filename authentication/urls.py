from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import (LoginApiView, PasswordTokenCheckAPIView, RegisterView,
                    RequestPasswordResetEmail, SetNewPasswordAPIView,
                    VerifyEmail, LogoutAPIView)

urlpatterns = [
    path('register/', RegisterView.as_view(), name="register"),
    path('login/', LoginApiView.as_view(), name="login"),
    path('logout/', LogoutAPIView.as_view(), name="logout"),
    path('email-verify/', VerifyEmail.as_view(), name="email-verify"),
    path('token-refresh/', TokenRefreshView.as_view(), name="token-refresh"),
    path('request-reset-email/', RequestPasswordResetEmail.as_view(),
         name="request-reset-email"),
    path('password-reset/<uidb64>/<token>',
         PasswordTokenCheckAPIView.as_view(), name="password-reset-confirm"),
    path('password-reset-complete/',
         SetNewPasswordAPIView.as_view(), name="password-reset-complete"),
]
