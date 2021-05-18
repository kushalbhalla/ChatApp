from django.contrib.auth import get_user_model, authenticate
from django.utils.translation import ugettext_lazy as _
from rest_framework import serializers

from .models import Customer, Message


class UserSerializer(serializers.ModelSerializer):
    """Serializer for the user object """

    class Meta:
        model = get_user_model()
        fields = ('id', 'email', 'password', 'name')
        extra_kwargs = {'password': {'write_only': True, 'min_length': 5}}

    def create(self, validated_data):
        """ Create a new user with encrypted password and return it"""
        return get_user_model().objects.create_user(**validated_data)


class AuthTokenSerializer(serializers.Serializer):
    """Serializer for the user authentication object"""

    email = serializers.CharField()
    password = serializers.CharField(
        style={'input_type': 'password'},
        trim_whitespace=False
    )

    def validate(self, attrs):
        """Validate and authenticate the user"""
        email = attrs.get('email')
        password = attrs.get('password')

        user = authenticate(
            request=self.context.get('request'),
            username=email,
            password=password
        )
        if not user:
            msg = ('Unable to authenticate with provided credentials')
            raise serializers.ValidationError(msg, code='authentication')

        attrs['user'] = user
        return attrs


class ChangePasswordSerializer(serializers.Serializer):
    """Serializer for changing user password"""

    model = get_user_model()

    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)


class CustomSerializer(serializers.ModelSerializer):
    """Serializer for creating a cutomer"""

    class Meta:
        model = Customer
        fields = ('id', 'nickname', 'phone', 'language', 'dob', 'pic')


class CustomSerializerA(serializers.ModelSerializer):
    """Serializer for customer with an extra user field"""

    class Meta:
        model = Customer
        fields = ('id', 'nickname', 'phone', 'language', 'dob', 'pic', 'user')


class MessageSerializer(serializers.ModelSerializer):
    """Serializer for message"""
    
    class Meta:
        model = Message
        fields = ('id', 'sender', 'receiver', 'msg')


class MessageSerializerA(serializers.ModelSerializer):
    """Serializer for message with status extra field"""

    class Meta:
        model = Message
        fields = ('id', 'sender', 'receiver', 'msg', 'date', 'status')
