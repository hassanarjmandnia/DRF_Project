from django.core.validators import RegexValidator
from rest_framework import serializers
from .models import CustomUser


class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model = CustomUser
        fields = ["id", "username", "email", "first_name", "last_name", "password"]
        extra_kwargs = {"password": {"write_only": True}}

    def validate_first_name(self, value):
        if not value.isalpha():
            raise serializers.ValidationError("First name must contain only letters.")
        return value

    def validate_last_name(self, value):
        if not value.isalpha():
            raise serializers.ValidationError("Last name must contain only letters.")
        return value

    password_validator = RegexValidator(
        regex=r"^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[\W_])[a-zA-Z0-9\W_]{8,}$",
        message="Password must contain at least one digit, one uppercase letter, "
        "one lowercase letter, one special character, and be at least 8 characters long.",
    )

    def validate_password(self, value):
        self.password_validator(value)
        return value

    def create(self, validated_data):
        password = validated_data.pop("password")
        user = CustomUser.objects.create_user(password=password, **validated_data)
        return user
