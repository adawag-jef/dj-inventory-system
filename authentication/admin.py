from django.contrib import admin

from .models import User, UserProfile, Role, Permission

admin.site.register((User, UserProfile, Role, Permission))
