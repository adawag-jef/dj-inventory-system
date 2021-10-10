
from django.contrib import auth
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.sites.shortcuts import get_current_site
from django.core.exceptions import ValidationError
from django.urls import reverse
from django.utils.encoding import (DjangoUnicodeDecodeError, force_str,
                                   smart_bytes, smart_str)
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
import jwt
from django.conf import settings

from .models import Permission, Role, User, UserProfile


class RegisterSerializer(serializers.ModelSerializer):

    password = serializers.CharField(
        max_length=68, min_length=6, write_only=True)

    class Meta:
        model = User
        fields = ['email', 'username', 'password']

    def validate(self, attrs):
        email = attrs.get('email', '')
        username = attrs.get('username', '')

        if not username.isalnum():
            raise serializers.ValidationError(
                'The username should only contain alphanumeric characters')

        return attrs

    def create(self, validated_data):

        return User.objects.create_user(**validated_data)


class EmailVerificationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=255)

    class Meta:
        model = User
        fields = ['token']


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=3)
    password = serializers.CharField(
        max_length=68, min_length=6, write_only=True)
    username = serializers.CharField(
        max_length=68, min_length=6, read_only=True)
    tokens = serializers.SerializerMethodField()

    def get_tokens(self, obj):
        user = User.objects.get(email=obj['email'])
        return {
            'access': user.tokens()['access'],
            'refresh': user.tokens()['refresh']
        }

    class Meta:
        model = User
        fields = ['email', 'password', 'username', 'tokens']

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')

        user = auth.authenticate(email=email, password=password)

        if not user:
            raise AuthenticationFailed('Invalid credentials')
        if not user.is_active:
            raise AuthenticationFailed('Account disabled, contact admin')
        if not user.is_verified:
            raise AuthenticationFailed('Email is not verified')

        return {
            'email': user.email,
            'username': user.username,
            'tokens': user.tokens()
        }


class RequestPasswordEmailRequestSerializer(serializers.Serializer):

    email = serializers.EmailField(min_length=2)
    redirect_url = serializers.CharField(max_length=500, required=False)

    class Meta:
        fields = ['email', 'redirect_url']


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(
        min_length=6, max_length=68, write_only=True)
    token = serializers.CharField(min_length=1, write_only=True)
    uidb64 = serializers.CharField(min_length=1, write_only=True)

    class Meta:
        fields = ['password',
                  'token',
                  'uidb64']

    def validate(self, attrs):
        try:
            password = attrs.get('password', '')
            token = attrs.get('token', '')
            uidb64 = attrs.get('uidb64', '')

            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                raise AuthenticationFailed('The reset link is invalid.', 401)

            user.set_password(password)
            user.save()

            return user

        except Exception as e:
            raise AuthenticationFailed('The reset link is invalid.', 401)


class LogoutSerializer(serializers.Serializer):

    refresh = serializers.CharField()

    default_error_messages = {
        'bad_token': ('Token is expired or invalid',)
    }

    def validate(self, attrs):
        self.token = attrs['refresh']

        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            self.fail('bad_token')


class ProfileSerializer(serializers.ModelSerializer):
    # profile_picture = serializers.CharField(max_length=255, read_only=True)

    class Meta:
        model = UserProfile
        fields = ('profile_picture',
                  'first_name',
                  'last_name',
                  'gender',
                  'birthday',)


class UserSerializer(serializers.ModelSerializer):

    password = serializers.CharField(
        max_length=68, min_length=6, write_only=True)
    # user_profile = ProfileSerializer()

    def to_representation(self, instance):
        ret = super().to_representation(instance)

        role = RoleSerializer(instance.role).data
        ret['role'] = role
        return ret

    class Meta:
        model = User
        fields = ('id', 'email', 'username', 'password',
                  'created_at', 'updated_at', 'user_profile', 'role')
        read_only_fields = ['user_profile']

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class UserProfileSerializer(serializers.ModelSerializer):

    user = UserSerializer(read_only=True)

    class Meta:
        model = UserProfile
        fields = '__all__'
        # read_only_fields = ['user']


class PermissionSerializer(serializers.ModelSerializer):

    class Meta:
        model = Permission
        fields = '__all__'


class RoleSerializer(serializers.ModelSerializer):

    # permissions = PermissionSerializer(many=True, partial=True)
    def to_representation(self, instance):
        ret = super().to_representation(instance)

        permissions = PermissionSerializer(
            instance.permissions, many=True).data
        ret['permissions'] = permissions
        return ret

    class Meta:
        model = Role
        fields = '__all__'


class TokenVerficationSerializer(serializers.Serializer):
    token = serializers.CharField(max_length=255, write_only=True)
    user = UserSerializer(read_only=True)

    def validate(self, attrs):
        token = attrs['token']
        try:
            payload = jwt.decode(
                token, settings.SECRET_KEY, algorithms='HS256')
            user = User.objects.get(id=payload['user_id'])
            attrs['user'] = user
            return super().validate(attrs)

        except jwt.ExpiredSignatureError as identifier:
            raise ValidationError({'error': 'Token is expired'})
        except jwt.exceptions.DecodeError as identifier:
            raise ValidationError({'error': 'Token is invalid'})
