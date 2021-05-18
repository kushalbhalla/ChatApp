from django.db import models
from django.contrib.auth.models import User
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin

from django.dispatch import receiver
from django.urls import reverse
from django_rest_passwordreset.signals import reset_password_token_created
from django.core.mail import send_mail


@receiver(reset_password_token_created)
def password_reset_token_created(sender, instance, reset_password_token, *args, **kwargs):

    email_plaintext_message = "{}?token={}".format(reverse('password_reset:reset-password-request'), reset_password_token.key)

    send_mail(
        # title:
        "Password Reset for {title}".format(title="Some website title"),
        # message:
        email_plaintext_message,
        # from:
        "noreply@somehost.local",
        # to:
        [reset_password_token.user.email]
    )


class UserManager(BaseUserManager):

    def create_user(self, email, password=None, **extra_fields):
        """creates and saves a new user"""
        if not email:
            raise ValueError('User must have an email address')
        user = self.model(email=self.normalize_email(email), **extra_fields)
        user.set_password(password)
        user.save()

        return user

    def create_superuser(self, email, password):
        """Creates and saves a new super user"""
        user = self.create_user(email, password)
        user.is_staff = True
        user.is_superuser = True
        user.save()

        return user


class User(AbstractBaseUser, PermissionsMixin):
    """ Custoom user model that support using email instead of username"""
    
    email = models.EmailField(max_length=255, unique=True)
    name = models.CharField(max_length=255)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'email'


class Customer(models.Model):
    """Create a customer model by a specific user"""

    user = models.ForeignKey(User, on_delete=models.CASCADE, default=4)
    nickname = models.CharField(max_length=100)
    language = models.CharField(max_length=100)
    phone = models.CharField(max_length=100)
    dob = models.DateField(null=True)
    pic = models.CharField(max_length=100)

    def __str__(self):
        return self.nickname


class Message(models.Model):
    """Create a message mode"""

    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='senderuser')
    receiver = models.ForeignKey(User, on_delete=models.CASCADE)
    msg = models.CharField(max_length=1000)
    date = models.DateTimeField()
    status = models.BooleanField(default=False)
