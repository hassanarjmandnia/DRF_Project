from .models import CustomUser, Product, ProductFile, Sale, SaleProduct
from django.core.validators import RegexValidator
from rest_framework import serializers
from .utils import get_default_role
from django.conf import settings
import re


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
        default_role = get_default_role()
        if default_role is None:
            raise serializers.ValidationError(
                "Sorry, we are unable to process your registration request at this time. Please try again later."
            )
        validated_data["role"] = default_role
        password = validated_data.pop("password")
        user = CustomUser.objects.create_user(password=password, **validated_data)
        return user


class ProductFileSerializer(serializers.ModelSerializer):
    file_url = serializers.SerializerMethodField()
    original_name = serializers.CharField(source="file.name", read_only=True)
    file_format = serializers.CharField(read_only=True)
    file_size = serializers.IntegerField(read_only=True)

    class Meta:
        model = ProductFile
        fields = ["id", "file", "file_url", "original_name", "file_format", "file_size"]

    def get_file_url(self, obj):
        request = self.context.get("request")
        if obj.file:
            return request.build_absolute_uri(obj.file.url)
        return None


class ProductCreateSerializer(serializers.ModelSerializer):

    files = serializers.ListField(
        child=serializers.FileField(), write_only=True, allow_empty=False
    )
    file_details = ProductFileSerializer(source="files", many=True, read_only=True)

    class Meta:
        model = Product
        fields = [
            "id",
            "title",
            "description",
            "price",
            "files",
            "file_details",
            "user_id",
            "quantity",
        ]

    def validate_title(self, value):
        if not value.strip():
            raise serializers.ValidationError("Title cannot be blank.")
        if not re.match(r"^[a-zA-Z0-9\s]+$", value):
            raise serializers.ValidationError("Title must be alphanumeric.")
        if len(value) < 10:
            raise serializers.ValidationError(
                "Title must be at least 10 characters long."
            )
        return value

    def validate_description(self, value):
        if not value.strip():
            raise serializers.ValidationError("Description cannot be blank.")
        if len(value) < 10:
            raise serializers.ValidationError(
                "Description must be at least 10 characters long."
            )
        return value

    def validate_price(self, value):
        if value is None or value <= 0:
            raise serializers.ValidationError("Price must be greater than zero.")
        return value

    def validate_files(self, files):
        if not (1 <= len(files) <= 5):
            raise serializers.ValidationError(
                "Number of files must be between 1 and 5."
            )
        total_size = 0
        for file in files:
            if not any(
                file.name.endswith(ext) for ext in settings.ALLOWED_FILE_UPLOAD_FORMATS
            ):
                raise serializers.ValidationError(
                    f"Invalid file type. Allowed types are: {', '.join(settings.ALLOWED_FILE_UPLOAD_FORMATS)}"
                )
            total_size += file.size
        if total_size > settings.MAX_FILE_UPLOAD_SIZE:
            raise serializers.ValidationError(
                f"Total file size must be under {settings.MAX_FILE_UPLOAD_SIZE / (1024 * 1024)} MB"
            )
        return files

    def create(self, validated_data):
        files = validated_data.pop("files", [])
        product = Product.objects.create(**validated_data)
        return product


class ProductReadSerializer(serializers.ModelSerializer):

    class Meta:
        model = Product
        fields = ["id", "title", "description", "price", "user_id", "quantity"]


class ProductDetailSerializer(serializers.ModelSerializer):
    files = ProductFileSerializer(many=True)

    class Meta:
        model = Product
        fields = ["id", "title", "description", "price", "files", "user_id", "quantity"]


class ProductUpdateSerializer(serializers.ModelSerializer):
    files = serializers.ListField(
        child=serializers.FileField(), write_only=True, required=False
    )

    class Meta:
        model = Product
        fields = ["title", "description", "price", "quantity", "files"]
        extra_kwargs = {field: {"required": False} for field in fields}

    def validate_title(self, value):
        if not value.strip():
            raise serializers.ValidationError("Title cannot be blank.")
        if not re.match(r"^[a-zA-Z0-9\s]+$", value):
            raise serializers.ValidationError("Title must be alphanumeric.")
        if len(value) < 10:
            raise serializers.ValidationError(
                "Title must be at least 10 characters long."
            )
        return value

    def validate_description(self, value):
        if not value.strip():
            raise serializers.ValidationError("Description cannot be blank.")
        if len(value) < 10:
            raise serializers.ValidationError(
                "Description must be at least 10 characters long."
            )
        return value

    def validate_price(self, value):
        if value is None or value <= 0:
            raise serializers.ValidationError("Price must be greater than zero.")
        return value

    def validate_files(self, files):
        if not (1 <= len(files) <= 5):
            raise serializers.ValidationError(
                "Number of files must be between 1 and 5."
            )
        total_size = 0
        for file in files:
            if not any(
                file.name.endswith(ext) for ext in settings.ALLOWED_FILE_UPLOAD_FORMATS
            ):
                raise serializers.ValidationError(
                    f"Invalid file type. Allowed types are: {', '.join(settings.ALLOWED_FILE_UPLOAD_FORMATS)}"
                )
            total_size += file.size
        if total_size > settings.MAX_FILE_UPLOAD_SIZE:
            raise serializers.ValidationError(
                f"Total file size must be under {settings.MAX_FILE_UPLOAD_SIZE / (1024 * 1024)} MB"
            )
        return files

    def validate(self, data):
        if not data:
            raise serializers.ValidationError("At least one field must be updated.")
        return data

    def update(self, instance, validated_data):
        files = validated_data.pop("files", None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        if files:
            product_files = ProductFile.objects.filter(product=instance)
            for product_file in product_files:
                product_file.file.delete()
                product_file.delete()
            files_data = [{"file": file} for file in files]
            product_file_serializer = ProductFileSerializer(data=files_data, many=True)
            if product_file_serializer.is_valid():
                product_file_serializer.save(product=instance)
            else:
                raise serializers.ValidationError(product_file_serializer.errors)

        return instance


class SaleProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = SaleProduct
        fields = ["product", "quantity", "price"]


class ProductSaleSerializer(serializers.ModelSerializer):
    saleproduct_set = SaleProductSerializer(many=True, read_only=True)

    class Meta:
        model = Sale
        fields = ["id", "buyer", "total_price", "created_at", "saleproduct_set"]
        extra_kwargs = {"total_price": {"read_only": True}}

    def create(self, validated_data):
        sale = Sale.objects.create(**validated_data)
        return sale
