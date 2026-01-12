from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import get_user_model
from .models import CustomUser
import re

User = get_user_model()


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = (
            'email',
            'password',
            'password2',
            'phone',
            'avatar',
        )

    def validate_password(self, value):
        validate_password(value)
        return value

    def validate_phone(self, value):
        pattern = r'^\+380\d{9}$'
        if not re.match(pattern, value):
            raise serializers.ValidationError(
                "Телефон має бути у форматі +380XXXXXXXXX"
            )
        return value

    def validate_avatar(self, value):
        if value.size > 2 * 1024 * 1024:
            raise serializers.ValidationError("Фото більше 2MB")
        if not value.content_type.startswith('image/'):
            raise serializers.ValidationError("Файл має бути зображенням")
        return value

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError(
                {"password": "Паролі не співпадають"}
            )
        return attrs

    def create(self, validated_data):
        validated_data.pop('password2')

        user = CustomUser.objects.create_user(
            email=validated_data['email'],
            password=validated_data['password'],
            phone=validated_data.get('phone'),
            avatar=validated_data.get('avatar')
        )
        return user


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()


class PasswordResetConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True)

    def validate_new_password(self, value):
        validate_password(value)
        return value