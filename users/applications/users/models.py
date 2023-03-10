from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
#
from .managers import UserManager

# Create your models here.
class User(AbstractBaseUser, PermissionsMixin):
    
    GENDER_CHOICES = (
        ('M', 'Masculino'),
        ('F', 'Femenino'),
        ('O', 'Otros'),
    )

    username = models.CharField(max_length=11, unique=True)
    email = models.EmailField()
    names = models.CharField(max_length=30, blank=True)
    surnames = models.CharField(max_length=30, blank=True)
    gender = models.CharField(
        max_length=1,
        choices=GENDER_CHOICES,
        blank=True,
    )
    codregister = models.CharField(max_length=6, default='000000')
    #
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)

    USERNAME_FIELD = 'username'

    REQUIRED_FIELDS = ['email']

    objects = UserManager()

    def get_short_name(self):
        return self.username
    
    def get_full_name(self):
        return f"{self.names} {self.surnames}"
