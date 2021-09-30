from django.urls import path, include
from rest_framework_simplejwt.views import TokenRefreshView
from rest_framework.routers import DefaultRouter

from .views import (LoginApiView, PasswordTokenCheckAPIView, RegisterView,
                    RequestPasswordResetEmail, SetNewPasswordAPIView,
                    VerifyEmail, LogoutAPIView, UserProfileDetailAPIView, UserViewset, UserProfileViewset, UserAPIView, UserDetailAPIView, UserProfileAPIView,
                    UserProfileDetailAPIView, RoleViewset, PermissionViewset)


router = DefaultRouter()

router.register('users', UserViewset)
router.register('profile', UserProfileViewset)
router.register('role', RoleViewset)
router.register('permission', PermissionViewset)

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
    #     path('user/', UserAPIView.as_view(), name="user"),
    #     path('user/<int:id>/', UserDetailAPIView.as_view(), name="user-detail"),
    #     path('profile/', UserProfileAPIView.as_view(), name="user-profile"),
    #     path('profile/<int:id>/', UserProfileDetailAPIView.as_view(),
    #          name="user-profile-detail"),

    path('', include(router.urls))
]
