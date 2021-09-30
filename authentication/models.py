from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from rest_framework_simplejwt.tokens import RefreshToken
from django.db.models.signals import post_save
from django.dispatch import receiver
from cloudinary.models import CloudinaryField


class UserManager(BaseUserManager):

    def create_user(self, username, email, password=None, **kwargs):

        if username is None:
            raise TypeError('Users should have a username')
        if email is None:
            raise TypeError('Users should have an email')

        user = self.model(username=username, email=self.normalize_email(email))
        user.set_password(password)
        user.save()

        # user_profile = kwargs.get('user_profile', {})

        # profile = UserProfile(
        #     user=user, profile_picture=str(os.environ.get('DEFAULT_PROFILE_PIC')), **user_profile)
        # profile.save()
        return user

    def create_superuser(self, username, email, password):

        if password is None:
            raise TypeError('Password should not be none')

        user = self.create_user(username, email, password)
        user.is_superuser = True
        user.is_staff = True
        user.save()

        return user


class Permission(models.Model):
    title = models.CharField(max_length=20, unique=True)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title


class Role(models.Model):
    title = models.CharField(max_length=20, unique=True)
    description = models.TextField()
    permissions = models.ManyToManyField(
        Permission, related_name="permission_role")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title


class User(AbstractBaseUser, PermissionsMixin):

    username = models.CharField(max_length=255, unique=True, db_index=True)
    email = models.EmailField(max_length=255, unique=True, db_index=True)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    role = models.ForeignKey(
        Role, related_name='user_role', on_delete=models.DO_NOTHING, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    objects = UserManager()

    def __str__(self):
        return self.email

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token)
        }


class UserProfile(models.Model):

    GENDER_OPTIONS = (
        ('MALE', 'MALE'),
        ('FEMALE', 'FEMALE'),
    )

    user = models.OneToOneField(
        User, related_name='user_profile', on_delete=models.CASCADE)
    # profile_picture = models.ImageField(
    #     upload_to="profile_pics", default='ball.png')
    first_name = models.CharField(blank=True, null=True, max_length=255)
    last_name = models.CharField(blank=True, null=True, max_length=255)
    gender = models.CharField(choices=GENDER_OPTIONS,
                              max_length=20, null=True, blank=True)
    birthday = models.DateField(null=True, blank=True)
    profile_picture = CloudinaryField('image', blank=True, null=True)

    def __str__(self):
        return self.user.email


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.create(user=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    instance.user_profile.save()
