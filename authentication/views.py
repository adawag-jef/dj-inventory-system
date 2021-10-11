import os

import cloudinary
import cloudinary.uploader
import jwt
from django.conf import settings
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.encoding import (DjangoUnicodeDecodeError, force_str,
                                   smart_bytes, smart_str)
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import (generics, mixins, permissions, status, views,
                            viewsets, filters)
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken

from .models import Permission, Role, User, UserProfile
from .permissions import UserActionPermission
from .renderers import UserRenderer
from .serializers import (EmailVerificationSerializer, LoginSerializer,
                          LogoutSerializer, PermissionSerializer,
                          RegisterSerializer,
                          RequestPasswordEmailRequestSerializer,
                          RoleSerializer, SetNewPasswordSerializer, TokenVerficationSerializer,
                          UserProfileSerializer, UserSerializer)
from .utils import Util


class RegisterView(generics.GenericAPIView):

    serializer_class = RegisterSerializer
    renderer_classes = (UserRenderer,)

    def post(self, request):
        user = request.data
        serializer = self.serializer_class(data=user)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        user_data = serializer.data

        user = User.objects.get(email=user_data['email'])

        token = RefreshToken.for_user(user).access_token

        current_site = get_current_site(request).domain
        relative_link = reverse('email-verify')
        absurl = 'http://' + current_site+relative_link+'?token='+str(token)
        email_body = 'Hi ' + user.username + \
            'use link below to verify your email \n' + absurl
        data = {
            'email_body': email_body,
            'email_subject': 'Verify your email',
            'to_email': user.email
        }
        Util.send_email(data)

        return Response(user_data, status=status.HTTP_201_CREATED)


class VerifyEmail(views.APIView):
    serializer_class = EmailVerificationSerializer

    token_param_config = openapi.Parameter(
        'token', in_=openapi.IN_QUERY, description='Description', type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request):
        token = request.GET.get('token')
        try:
            payload = jwt.decode(
                token, settings.SECRET_KEY, algorithms='HS256')
            user = User.objects.get(id=payload['user_id'])
            if not user.is_verified:
                user.is_verified = True
                user.save()

            return Response({'email': 'Successfully Activated'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as identifier:
            return Response({'error': 'Activation Link expired'}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            return Response({'error': 'Invalid token'}, status=status.HTTP_400_BAD_REQUEST)


class LoginApiView(generics.GenericAPIView):

    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.data, status=status.HTTP_200_OK)


class RequestPasswordResetEmail(generics.GenericAPIView):

    serializer_class = RequestPasswordEmailRequestSerializer

    def post(self, request):
        data = {'request': request, 'data': request.data}
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = request.data['email']

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uidb64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user)

            current_site = get_current_site(request).domain
            # relative_link = reverse(
            #     'password-reset-confirm', kwargs={'uidb64': uidb64, 'token': token})
            # absurl = 'http://' + current_site + relative_link
            redirect_url = request.data.get('redirect_url', '')
            absurl = os.environ.get(
                'FRONTEND_URL') + '/password-reset/' + uidb64 + '/' + token + '/'
            email_body = 'Hello \n use link to reset password \n' + \
                absurl + "?redirect_url="+redirect_url
            data = {
                'email_body': email_body,
                'email_subject': 'Reset Password',
                'to_email': user.email
            }
            Util.send_email(data)

        return Response({'success': 'We have sent you a link to reset your password'}, status=status.HTTP_200_OK)


class PasswordTokenCheckAPIView(generics.GenericAPIView):
    serializer_class = SetNewPasswordSerializer

    def get(self, request, uidb64, token):
        redirect_url = request.GET.get('redirect_url')
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):

                if len(redirect_url) > 3:
                    return redirect(redirect_url + "?token_valid=False")
                else:
                    return redirect(os.environ.get('FRONTEND_URL') + "?token_valid=False")

                # return Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_401_UNAUTHORIZED)
            if len(redirect_url) > 3:
                return redirect(redirect_url + "?token_valid=True&uidb64=" + uidb64 + "&token="+token)
            else:
                return redirect(os.environ.get('FRONTEND_URL') + "?token_valid=True&uidb64=" + uidb64 + "&token="+token)

            # return Response({'success': True, 'message': 'Credentials Valid', 'uidb64': uidb64, 'token': token}, status=status.HTTP_200_OK)
        except DjangoUnicodeDecodeError as identifier:
            return redirect(redirect_url + "?token_valid=False")
            # return Response({'error': 'Token is not valid, please request a new one'}, status=status.HTTP_401_UNAUTHORIZED)


class SetNewPasswordAPIView(generics.GenericAPIView):

    serializer_class = SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Password reset success'}, status=status.HTTP_200_OK)


class LogoutAPIView(generics.GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = (permissions.IsAuthenticated,)

    def post(self, request):

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(status=status.HTTP_204_NO_CONTENT)


class VerifyTokenAPIView(views.APIView):
    serializer_class = TokenVerficationSerializer

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'token': openapi.Schema(type=openapi.TYPE_STRING, description='string'),
        }
    ))
    def post(self, request):

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        return Response(serializer.data, status=status.HTTP_200_OK)


class UserViewset(viewsets.ModelViewSet):

    serializer_class = UserSerializer
    queryset = User.objects.all()

    permission_classes = [permissions.IsAuthenticated, UserActionPermission]
    filter_backends = [filters.OrderingFilter, filters.SearchFilter]
    ordering_fields = ['id', 'username', 'email']
    search_fields = ['id', 'username', 'email']

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.user_profile.profile_picture.public_id != "default":
            cloudinary.uploader.destroy(
                instance.user_profile.profile_picture.public_id, invalidate=True)
        self.perform_destroy(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)


class UserProfileViewset(viewsets.ModelViewSet):

    serializer_class = UserProfileSerializer
    queryset = UserProfile.objects.all()
    permission_classes = [permissions.IsAuthenticated, UserActionPermission]
    filter_backends = [filters.OrderingFilter, filters.SearchFilter]
    ordering_fields = ['id',
                       'first_name',
                       'last_name',
                       'gender',
                       'birthday']
    search_fields = ['id',
                     'first_name',
                     'last_name',
                     'gender',
                     'birthday']

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        if request.FILES:
            if instance.profile_picture.public_id != "default":
                cloudinary.uploader.destroy(
                    instance.profile_picture.public_id, invalidate=True)
        serializer = self.get_serializer(
            instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)

        if getattr(instance, '_prefetched_objects_cache', None):
            instance._prefetched_objects_cache = {}

        return Response(serializer.data)


class RoleViewset(viewsets.ModelViewSet):

    serializer_class = RoleSerializer
    queryset = Role.objects.all()
    # permission_classes = [permissions.IsAuthenticated, UserActionPermission]
    filter_backends = [filters.OrderingFilter, filters.SearchFilter]
    ordering_fields = ['id', 'title', 'description', 'created_at']
    search_fields = ['id', 'title', 'description']

    pages_params = openapi.Parameter(
        'pages', in_=openapi.IN_QUERY, description='set to All to get unpaginated list', type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[pages_params])
    def list(self, request, *args, **kwargs):

        if request.query_params.get('pages') == 'All':

            roles = Role.objects.all()
            serializer = self.get_serializer(roles, many=True)
            return Response(serializer.data)

        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


class PermissionViewset(viewsets.ModelViewSet):

    serializer_class = PermissionSerializer
    queryset = Permission.objects.all()
    permission_classes = [permissions.IsAuthenticated, UserActionPermission]
    filter_backends = [filters.OrderingFilter, filters.SearchFilter]
    ordering_fields = ['id', 'title', 'description', 'created_at']
    search_fields = ['id', 'title', 'description']

    pages_param = openapi.Parameter(
        'pages', in_=openapi.IN_QUERY, description='set to All to get unpaginated list', type=openapi.TYPE_STRING)

    @swagger_auto_schema(manual_parameters=[pages_param])
    def list(self, request, *args, **kwargs):

        if request.query_params.get('pages') == 'All':

            permissions = Permission.objects.all()
            serializer = self.get_serializer(permissions, many=True)
            return Response(serializer.data)

        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)


# Generic Views backup
class UserAPIView(generics.ListCreateAPIView):

    serializer_class = UserSerializer
    queryset = User.objects.all()


class UserDetailAPIView(generics.RetrieveUpdateDestroyAPIView):

    serializer_class = UserSerializer
    queryset = User.objects.all()
    lookup_field = 'id'


class UserProfileAPIView(generics.ListCreateAPIView):

    serializer_class = UserProfileSerializer
    queryset = UserProfile.objects.all()


class UserProfileDetailAPIView(generics.GenericAPIView, mixins.RetrieveModelMixin, mixins.UpdateModelMixin):

    serializer_class = UserProfileSerializer
    queryset = UserProfile.objects.all()
    lookup_field = 'id'

    def put(self, request, *args, **kwargs):
        return self.partial_update(request, *args, **kwargs)

    def get(self, request, *args, **kwargs):
        return self.retrieve(request, *args, **kwargs)
