from rest_framework.permissions import BasePermission, IsAuthenticated, SAFE_METHODS
from django.contrib.auth import login, authenticate, logout
from rest_framework.exceptions import PermissionDenied
from .models import Product, ProductFile, Sale
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from django.conf import settings
from .serializers import (
    ProductCreateSerializer,
    ProductDetailSerializer,
    ProductUpdateSerializer,
    ProductFileSerializer,
    ProductSaleSerializer,
    UserSerializer,
)
import logging

info_logger = logging.getLogger("info_logger")
error_logger = logging.getLogger("error_logger")


class IsAuthenticatedOrReadOnly(BasePermission):
    def has_permission(self, request, view):
        if request.method in SAFE_METHODS:  # SAFE_METHODS = ['GET', 'OPTIONS', 'HEAD']
            return True
        return request.user and request.user.is_authenticated


class IsSuperAdmin(BasePermission):
    """
    Custom permission to only allow superadmin users to access the view.
    """

    def has_permission(self, request, view):
        # Check if the user is authenticated and is a superadmin
        return (
            request.user
            and request.user.is_authenticated
            and request.user.role.name == "superadmin"
        )


class UserRegistrationView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            login(request, user)
            info_logger.info(f"User '{user.username}' registered successfully.")
            return Response(
                {"message": "User registered successfully"},
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            info_logger.info(f"User '{user.username}' logged_in successfully.")
            return Response(
                {"message": "Login successful"},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"message": "Invalid credentials"},
                status=status.HTTP_401_UNAUTHORIZED,
            )


class UserLogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        username = request.user.username
        info_logger.info(f"User '{username}' logged out successfully.")
        logout(request)
        return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)


class MyProtectedView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"message": f"Hello, {request.user.username}!"})


class ProductView(APIView):
    permission_classes = [IsAuthenticatedOrReadOnly]

    def get(self, request):
        products = Product.objects.all()
        serializer = ProductDetailSerializer(
            products, context={"request": request}, many=True
        )
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        files_data = [{"file": file} for file in request.FILES.getlist("files")]
        product_serializer = ProductCreateSerializer(
            data=request.data, context={"request": request}
        )
        product_file_serializer = ProductFileSerializer(data=files_data, many=True)
        if product_serializer.is_valid():
            if product_file_serializer.is_valid():
                product = product_serializer.save(user=request.user)
                product_file_serializer.save(product=product)
                info_logger.info(
                    f"Product '{product.id}' with {len(files_data)} created successfully."
                )
                print(product_serializer.data)
                file_urls = [
                    file_data["file_url"]
                    for file_data in product_serializer.data["file_details"]
                ]
                response_data = product_serializer.data
                response_data["file_details"] = file_urls
                return Response(response_data, status=status.HTTP_201_CREATED)
            else:
                return Response(
                    product_file_serializer.errors, status=status.HTTP_400_BAD_REQUEST
                )
        else:
            return Response(
                product_serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )


class SpecificProductView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, pk):
        try:
            product = Product.objects.get(pk=pk)
        except Product.DoesNotExist:
            return Response(
                {"error": "Product not found"}, status=status.HTTP_404_NOT_FOUND
            )
        if product.user == request.user or (
            request.user and request.user.role.name == "superadmin"
        ):
            if not request.data:
                return Response(
                    {"error": "No fields provided for update"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            serializer = ProductUpdateSerializer(
                product, data=request.data, partial=True
            )

            if serializer.is_valid():
                serializer.save()
                info_logger.info(f"Product '{product.id}' updated successfully.")
                return Response(
                    {"message": "Product and associated files updated successfully."},
                    status=status.HTTP_204_NO_CONTENT,
                )
            else:
                error_logger.error(
                    f"Update failed for Product '{product.id}': {serializer.errors}"
                )
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            raise PermissionDenied("You do not have permission to update this product.")

    def delete(self, request, pk):
        try:
            product = Product.objects.get(pk=pk)
        except Product.DoesNotExist:
            return Response(
                {"error": "Product not found"}, status=status.HTTP_404_NOT_FOUND
            )
        if product.user == request.user or (
            request.user and request.user.role.name == "superadmin"
        ):
            product_files = ProductFile.objects.filter(product=product)
            for product_file in product_files:
                product_file.file.delete()
                product_file.delete()
            info_logger.info(
                f"Product '{product.id}' and associated files deleted successfully."
            )
            product.delete()
            return Response(
                {"message": "Product and associated files deleted successfully."},
                status=status.HTTP_204_NO_CONTENT,
            )
        else:
            raise PermissionDenied("You do not have permission to delete this product.")


class SaleView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        try:
            product = Product.objects.get(pk=pk)
        except Product.DoesNotExist:
            return Response(
                {"error": "Product not found"}, status=status.HTTP_404_NOT_FOUND
            )
        quantity = int(request.data["quantity"])
        if quantity <= product.quantity:
            sale_data = {
                "buyer": request.user.id,
                "product": product.id,
                "price": product.price,
                "quantity": quantity,
            }
            sale_serializer = ProductSaleSerializer(data=sale_data)
            if sale_serializer.is_valid():
                sale_serializer.save()
                product.quantity -= quantity
                product.save()
                product_serializer = ProductDetailSerializer(
                    product, context={"request": request}
                )
                file_urls = [
                    file_data["file_url"]
                    for file_data in product_serializer.data["files"]
                ]
                response_data = product_serializer.data
                response_data["files"] = file_urls

                return Response(sale_serializer.data, status=status.HTTP_201_CREATED)
            else:
                return Response(
                    sale_serializer.errors, status=status.HTTP_400_BAD_REQUEST
                )
        else:
            return Response(
                "we don't have that much from this product right now, sorry",
                status=status.HTTP_400_BAD_REQUEST,
            )


class PurchaseHistoryView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        sales = Sale.objects.filter(buyer=request.user.id)
        serializer = ProductSaleSerializer(sales, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
