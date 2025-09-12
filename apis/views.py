import random
import re
import json
import traceback
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.http import HttpResponse
import csv
from django.shortcuts import render, redirect
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import update_session_auth_hash
from django.contrib import messages
import re
from django.db.models import Sum, IntegerField
from django.db.models.functions import Cast
from datetime import datetime
from django.shortcuts import render
from rest_framework import viewsets
from .models import Line, Area, Customer, Loan
from .serializers import LineSerializer, AreaSerializer, CustomerSerializer, LoanSerializer
from datetime import datetime
from django.db.models import Sum, Prefetch
from django.shortcuts import render
from django.db.models.functions import TruncMonth
from django.db.models import Count
from django.contrib import messages
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
import json
from django.utils import timezone
from django.shortcuts import render
from .models import Line, Area
from .models import Expense, Line
from django.shortcuts import render
from datetime import datetime
from .models import Expense, Line
from django.shortcuts import render, get_object_or_404
from apis.models import CustomUser
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from .models import Customer, Line, Area
from rest_framework import status
from django.shortcuts import render, redirect
from django.contrib.auth import get_user_model
from django.contrib import messages
from rest_framework import status
from datetime import date, timedelta
from django.utils import timezone
from django.http import JsonResponse, HttpResponseNotAllowed
from django.contrib.auth import get_user_model
from django.contrib import messages
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.shortcuts import redirect, render
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.shortcuts import render, redirect
from dateutil.relativedelta import relativedelta
from decimal import Decimal, InvalidOperation
from django.utils.timezone import now
from rest_framework.views import APIView
from django.db.models import Sum
from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from apis.models import CustomUser 
from django.shortcuts import render, redirect
from .models import Customer, Expense, Area, Payment
from django.http import JsonResponse
from django.contrib.auth import authenticate, login
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from rest_framework import generics, permissions, viewsets, status
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import serializers
from .serializers import CustomUserSerializer, PaymentSerializer, UserProfileUpdateSerializer, CustomerSerializer, ExpenseSerializer, AreaSerializer
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view, permission_classes
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.core.mail import send_mail
from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.utils.dateparse import parse_date
from django.views.decorators.http import require_GET
from django.contrib.auth.hashers import make_password
from django.db import IntegrityError, transaction
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from .models import Line
from .serializers import LineSerializer
from apis import models

User = get_user_model()

# ViewSets for REST API
class CustomerViewSet(viewsets.ModelViewSet):
    queryset = Customer.objects.all()
    serializer_class = CustomerSerializer
    permission_classes = [AllowAny]  # Change to IsAuthenticated for production
    
    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            return Response({
                'success': True,
                'message': 'Customer created successfully',
                'data': serializer.data
            }, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({
                'success': False,
                'message': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

class ExpenseViewSet(viewsets.ModelViewSet):
    queryset = Expense.objects.all()
    serializer_class = ExpenseSerializer
    permission_classes = [AllowAny]  # Change to IsAuthenticated for production
    
    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            return Response({
                'success': True,
                'message': 'Expense created successfully',
                'data': serializer.data
            }, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({
                'success': False,
                'message': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

class AreaViewSet(viewsets.ModelViewSet):
    queryset = Area.objects.all()
    serializer_class = AreaSerializer
    permission_classes = [AllowAny]  # Change to IsAuthenticated for production
    
    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            return Response({
                'success': True,
                'message': 'Area created successfully',
                'data': serializer.data
            }, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({
                'success': False,
                'message': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

class ProfileUpdateView(generics.UpdateAPIView):
    authentication_classes = []
    permission_classes = [IsAuthenticated]
    serializer_class = UserProfileUpdateSerializer

    def get_object(self):
        return self.request.user

    def put(self, request, *args, **kwargs):
        try:
            # Split full name into first and last names
            if 'name' in request.data:
                name_parts = request.data['name'].split(' ', 1)
                request.data['first_name'] = name_parts[0]
                request.data['last_name'] = name_parts[1] if len(name_parts) > 1 else ''
            
            instance = self.get_object()
            serializer = self.get_serializer(instance, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            self.perform_update(serializer)
            
            return Response({
                'status': 'success',
                'message': 'Profile updated successfully',
                'data': serializer.data
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'status': 'error',
                'message': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

def cron_task(request):
    return JsonResponse({"status": "corn task is hitted"})

def register_view(request):
    if request.method == 'POST':
        try:
            data = request.POST

            username = data.get('username', '').strip()
            email = data.get('email', '').strip()
            password = data.get('password', '')
            full_name = data.get('full_name', '').strip()
            mobile_number = data.get('mobile_number', '').strip()

            # ✅ 1. Required fields
            if not all([username, email, password, full_name, mobile_number]):
                return JsonResponse(
                    {"error": "All fields are required. Please complete the form."},
                    status=400
                )

            # ✅ 2. Email validation
            try:
                validate_email(email)
            except ValidationError:
                return JsonResponse(
                    {"error": "Invalid email format. Example: user@example.com"},
                    status=400
                )

            # ✅ 3. Mobile number validation
            if not re.fullmatch(r'^\d{10}$', mobile_number):
                return JsonResponse(
                    {"error": "Mobile number must be exactly 10 digits (no spaces, no symbols)."},
                    status=400
                )

            # ✅ 4. Username rules
            if len(username) < 4:
                return JsonResponse(
                    {"error": "Username must be at least 4 characters long."},
                    status=400
                )
            if User.objects.filter(username=username).exists():
                return JsonResponse(
                    {"error": f'The username "{username}" is already taken. Try another one.'},
                    status=409
                )

            # ✅ 5. Email uniqueness
            if User.objects.filter(email=email).exists():
                return JsonResponse(
                    {"error": f'The email "{email}" is already registered. Try logging in instead.'},
                    status=409
                )

            # ✅ 6. Password rules
            if len(password) < 8:
                return JsonResponse(
                    {"error": "Password must be at least 8 characters long."},
                    status=400
                )
            if not re.search(r'[A-Za-z]', password):
                return JsonResponse(
                    {"error": "Password must contain at least one letter."},
                    status=400
                )
            if not re.search(r'[0-9]', password):
                return JsonResponse(
                    {"error": "Password must contain at least one number."},
                    status=400
                )

            # ✅ 7. Role assignment logic
            created_by = request.user if request.user.is_authenticated else None
            if created_by and hasattr(created_by, "role"):
                if created_by.role == "superadmin":
                    role = "staff"
                elif created_by.role == "staff":
                    role = "agent"
                else:
                    role = "agent"
            else:
                role = "agent"

            # ✅ 8. User creation with safe transaction
            try:
                with transaction.atomic():
                    user = User.objects.create_user(
                        username=username,
                        email=email,
                        password=password,
                        full_name=full_name,
                        mobile_number=mobile_number,
                        role=role,
                        created_by=created_by
                    )
            except IntegrityError:
                return JsonResponse(
                    {"error": "There was a problem creating your account. Please try again."},
                    status=500
                )

            # ✅ Success
            return JsonResponse(
                {"message": "Registration successful!"},
                status=200
            )

        except Exception as e:
            # Log full traceback for developers
            print("REGISTER ERROR:", traceback.format_exc())
            return JsonResponse(
                {"error": "Something went wrong on our side. Please try again later."},
                status=500
            )

    # GET request → return form page
    return render(request, 'core/register.html')


@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def register_view_api(request):
    """
    API endpoint for user registration with detailed, user-friendly errors
    """

    username = request.data.get('username', '').strip()
    email = request.data.get('email', '').strip()
    password = request.data.get('password', '')

    # ✅ 1. Required fields
    if not username:
        return Response({
            'success': False,
            'field': 'username',
            'message': "Username is required. Please choose a unique username."
        }, status=status.HTTP_400_BAD_REQUEST)

    if not email:
        return Response({
            'success': False,
            'field': 'email',
            'message': "Email is required. Please provide a valid email address."
        }, status=status.HTTP_400_BAD_REQUEST)

    if not password:
        return Response({
            'success': False,
            'field': 'password',
            'message': "Password is required. Please set a strong password."
        }, status=status.HTTP_400_BAD_REQUEST)

    # ✅ 2. Validate email format
    try:
        validate_email(email)
    except ValidationError:
        return Response({
            'success': False,
            'field': 'email',
            'message': "The email address is not valid. Please use the format: user@example.com."
        }, status=status.HTTP_400_BAD_REQUEST)

    # ✅ 3. Username validation
    if len(username) < 4:
        return Response({
            'success': False,
            'field': 'username',
            'message': "Username is too short. It must be at least 4 characters long."
        }, status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(username=username).exists():
        return Response({
            'success': False,
            'field': 'username',
            'message': f"The username '{username}' is already taken. Please choose another one."
        }, status=status.HTTP_400_BAD_REQUEST)

    # ✅ 4. Email uniqueness
    if User.objects.filter(email=email).exists():
        return Response({
            'success': False,
            'field': 'email',
            'message': f"The email '{email}' is already registered. If you already have an account, please log in instead."
        }, status=status.HTTP_400_BAD_REQUEST)

    # ✅ 5. Password strength
    if len(password) < 8:
        return Response({
            'success': False,
            'field': 'password',
            'message': "Your password is too short. It must be at least 8 characters long."
        }, status=status.HTTP_400_BAD_REQUEST)

    if not re.search(r'[A-Za-z]', password):
        return Response({
            'success': False,
            'field': 'password',
            'message': "Weak password. Your password must contain at least one letter (A–Z or a–z)."
        }, status=status.HTTP_400_BAD_REQUEST)

    if not re.search(r'[0-9]', password):
        return Response({
            'success': False,
            'field': 'password',
            'message': "Weak password. Your password must contain at least one number (0–9)."
        }, status=status.HTTP_400_BAD_REQUEST)

    # ✅ 6. Create user
    user = User.objects.create_user(
        username=username,
        email=email,
        password=password
    )

    return Response({
        'success': True,
        'message': "🎉 Registration successful! You can now log in with your new account.",
        'user_id': user.id
    }, status=status.HTTP_201_CREATED)


def login_view(request):
    if request.method == 'POST' and request.headers.get('x-requested-with') == 'XMLHttpRequest':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()

        # ✅ 1. Username validation
        if not username:
            return JsonResponse({
                'success': False,
                'field': 'username',
                'error': "Username is required. Please enter your username."
            })

        # ✅ 2. Password validation
        if not password:
            return JsonResponse({
                'success': False,
                'field': 'password',
                'error': "Password is required. Please enter your password."
            })

        if len(password) < 6:
            return JsonResponse({
                'success': False,
                'field': 'password',
                'error': "Your password is too short. It must be at least 6 characters long."
            })

        # ✅ 3. Authenticate user
        user = authenticate(request, username=username, password=password)

        if user is not None:
            if not user.is_active:
                return JsonResponse({
                    'success': False,
                    'field': 'account',
                    'error': "Your account has been deactivated. Please contact support."
                })

            # Successful login
            login(request, user)
            return JsonResponse({
                'success': True,
                'role': user.role,
                'message': f"Welcome back, {user.full_name if hasattr(user, 'full_name') else user.username}!"
            })

        else:
            # Check if username exists to give specific error
            from .models import CustomUser
            if CustomUser.objects.filter(username=username).exists():
                return JsonResponse({
                    'success': False,
                    'field': 'password',
                    'error': "The password you entered is incorrect. Please try again."
                })
            else:
                return JsonResponse({
                    'success': False,
                    'field': 'username',
                    'error': f"No account found with the username '{username}'. Please check or register a new account."
                })

    return render(request, 'core/login.html')

@login_required
def license(request):
    user = request.user
    
    
    context = {
        'username': user.username,
        'annual_amount': '₹999',
        'valid_until': user.expiry_date if hasattr(user, 'expiry_date') else 'N/A'
    }
    
    return render(request, 'core/settingspages/license.html', context)

@login_required
def support(request):
    """
    Display support page
    """
    return render(request, 'core/settingspages/support.html')

@login_required
def agent_settings(request):
    return render(request, 'core/settingspages/Settings.html')

@login_required
def line_settings(request):
    """
    Display the Line Settings HTML page
    """
    user_lines = Line.objects.filter(created_by=request.user)
    return render(request, "core/LineSettings.html", {"lines": user_lines})

@login_required
def add_line(request):
    return render(request, 'core/LineAddCollection.html')

@login_required
def area_settings(request):
    areas = Area.objects.filter(created_by=request.user)
    return render(request, 'core/settingspages/AreaSettings.html', {'areas': areas, 'user': request.user})

@login_required
def add_area(request):
    if request.method == 'POST':
        area_name = request.POST.get('area_name', '').strip()

        # ✅ Check for empty input
        if not area_name:
            error_msg = "⚠️ Please enter an area name."
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'success': False, 'field': 'area_name', 'error': error_msg}, status=400)
            messages.error(request, error_msg)
            return redirect('area_settings')

        try:
            # ✅ Block duplicates only for the same user
            duplicate_exists = Area.objects.filter(
                name__iexact=area_name,
                created_by=request.user
            ).exists()

            if duplicate_exists:
                error_msg = f"❌ The area '{area_name}' already exists in your account."
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({'success': False, 'field': 'area_name', 'error': error_msg}, status=409)
                messages.error(request, error_msg)
                return redirect('area_settings')

            # ✅ Create the area
            Area.objects.create(
                name=area_name,
                created_by=request.user
            )

            success_msg = "🎉 Area added successfully!"
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'success': True, 'message': success_msg}, status=201)

            messages.success(request, success_msg)

        except Exception as e:
            error_msg = "🚨 Something went wrong while adding the area. Please try again."
            print(f"Add Area Error: {e}")
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'success': False, 'error': error_msg}, status=500)
            messages.error(request, error_msg)
            return redirect('area_settings')

    return render(request, 'core/settingspages/addArea.html')


def delete_area(request, area_id):
    """
    Handle deleting an area
    """
    try:
        area = Area.objects.get(id=area_id)
        area.delete()
        messages.success(request, 'Area deleted successfully!')
    except Area.DoesNotExist:
        messages.error(request, 'Area not found.')
    
    return redirect('area_settings')

@csrf_exempt
@login_required
def mysettings(request):
    """
    GET: Render HTML page (normal request) or return JSON (AJAX request).
    PUT: Update user details in DB with user-friendly error handling.
    """
    if request.method == "GET":
        # ✅ If AJAX request, return JSON profile data
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            try:
                user = CustomUser.objects.get(pk=request.user.pk)
                return JsonResponse({
                    "username": user.username,
                    "email": user.email,
                    "mobile_number": user.mobile_number,
                })
            except CustomUser.DoesNotExist:
                return JsonResponse({
                    "success": False,
                    "error": "User not found. Please log in again."
                }, status=404)

        # Otherwise render the settings page
        return render(request, 'core/settingspages/agentProfileEdit.html')

    elif request.method == "PUT":
        try:
            data = json.loads(request.body.decode("utf-8"))

            # ✅ Get current user
            try:
                user = CustomUser.objects.get(pk=request.user.pk)
            except CustomUser.DoesNotExist:
                return JsonResponse({
                    "success": False,
                    "error": "Your account could not be found. Please log in again."
                }, status=404)

            # ✅ Username validation
            if "username" in data:
                new_username = data["username"].strip()
                if not new_username:
                    return JsonResponse({"success": False, "field": "username",
                                         "error": "Username cannot be empty."}, status=400)
                if len(new_username) < 4:
                    return JsonResponse({"success": False, "field": "username",
                                         "error": "Username must be at least 4 characters long."}, status=400)
                if CustomUser.objects.filter(username=new_username).exclude(pk=user.pk).exists():
                    return JsonResponse({"success": False, "field": "username",
                                         "error": f"The username '{new_username}' is already taken."}, status=400)
                user.username = new_username

            # ✅ Email validation
            if "email" in data:
                new_email = data["email"].strip()
                if not new_email:
                    return JsonResponse({"success": False, "field": "email",
                                         "error": "Email cannot be empty."}, status=400)
                try:
                    validate_email(new_email)
                except ValidationError:
                    return JsonResponse({"success": False, "field": "email",
                                         "error": "Please enter a valid email address."}, status=400)
                if CustomUser.objects.filter(email=new_email).exclude(pk=user.pk).exists():
                    return JsonResponse({"success": False, "field": "email",
                                         "error": f"The email '{new_email}' is already in use."}, status=400)
                user.email = new_email

            # ✅ Mobile number validation
            if "mobile_number" in data:
                new_mobile = data["mobile_number"].strip()
                if not re.fullmatch(r"^\d{10}$", new_mobile):
                    return JsonResponse({"success": False, "field": "mobile_number",
                                         "error": "Mobile number must be exactly 10 digits."}, status=400)
                user.mobile_number = new_mobile

            # ✅ Save updates
            user.save()

            return JsonResponse({
                "success": True,
                "message": "🎉 Profile updated successfully!"
            }, status=200)

        except json.JSONDecodeError:
            return JsonResponse({
                "success": False,
                "error": "Invalid data format. Please send valid JSON."
            }, status=400)

        except Exception as e:
            return JsonResponse({
                "success": False,
                "error": "An unexpected error occurred. Please try again later."
            }, status=500)

    return JsonResponse({
        "success": False,
        "error": "Invalid request method. Please use GET or PUT."
    }, status=405)


@login_required
def languagae(request):
    """
    Display my settings page
    """
    return render(request, 'core/settingspages/LanguageSettings.html')

@login_required
def change_password(request):
    """Handle password change for logged-in user via AJAX with user-friendly errors"""
    if request.method == 'POST':
        try:
            # Get data from POST
            old_password = request.POST.get('oldPassword', '').strip()
            new_password = request.POST.get('newPassword', '').strip()
            confirm_password = request.POST.get('confirmPassword', '').strip()

            # ✅ 1. Empty fields
            if not old_password:
                return JsonResponse({'success': False, 'field': 'oldPassword',
                                     'error': "Please enter your current password."}, status=400)
            if not new_password:
                return JsonResponse({'success': False, 'field': 'newPassword',
                                     'error': "Please enter a new password."}, status=400)
            if not confirm_password:
                return JsonResponse({'success': False, 'field': 'confirmPassword',
                                     'error': "Please confirm your new password."}, status=400)

            # ✅ 2. Match check
            if new_password != confirm_password:
                return JsonResponse({'success': False, 'field': 'confirmPassword',
                                     'error': "The new passwords do not match. Please re-enter."}, status=400)

            # ✅ 3. Verify old password
            if not request.user.check_password(old_password):
                return JsonResponse({'success': False, 'field': 'oldPassword',
                                     'error': "The current password you entered is incorrect."}, status=400)

            # ✅ 4. Prevent reusing same password
            if old_password == new_password:
                return JsonResponse({'success': False, 'field': 'newPassword',
                                     'error': "Your new password cannot be the same as your current password."}, status=400)

            # ✅ 5. Strong password validation
            if len(new_password) < 8:
                return JsonResponse({'success': False, 'field': 'newPassword',
                                     'error': "Your password must be at least 8 characters long."}, status=400)
            if not re.search(r'[A-Z]', new_password):
                return JsonResponse({'success': False, 'field': 'newPassword',
                                     'error': "Your password must include at least one uppercase letter (A–Z)."}, status=400)
            if not re.search(r'[a-z]', new_password):
                return JsonResponse({'success': False, 'field': 'newPassword',
                                     'error': "Your password must include at least one lowercase letter (a–z)."}, status=400)
            if not re.search(r'[0-9]', new_password):
                return JsonResponse({'success': False, 'field': 'newPassword',
                                     'error': "Your password must include at least one number (0–9)."}, status=400)
            if not re.search(r'[!@#$%^&*()_+=\-`~\[\]{};:\'\"<>?,.\/\\|]', new_password):
                return JsonResponse({'success': False, 'field': 'newPassword',
                                     'error': "Your password must include at least one special character (!@#$ etc.)."}, status=400)

            # ✅ 6. Save new password securely
            request.user.set_password(new_password)
            request.user.save()

            # Keep user logged in
            update_session_auth_hash(request, request.user)

            return JsonResponse({'success': True, 'message': "🎉 Password changed successfully!"})

        except Exception as e:
            print(f"Password change error: {e}")  # log for debugging
            return JsonResponse({'success': False, 'error': "Something went wrong. Please try again later."}, status=500)

    # Render password change page for GET
    return render(request, 'core/settingspages/ChangePassword.html')

def signout(request):
    """
    Handle user logout
    """
    from django.contrib.auth import logout
    logout(request)
    messages.success(request, 'You have been successfully logged out.')
    return redirect('login')


@login_required
def add_customer(request):
    user = request.user

    if request.method == 'POST':
        try:
            customer_name = request.POST.get('name', '').strip()
            customer_code = request.POST.get('code', '').strip()
            mobile_number = request.POST.get('mobile_number', '').strip()
            line_id = request.POST.get('line', '').strip()
            area_id = request.POST.get('area', '').strip()
            status_value = request.POST.get('status', '').strip()
            maximum_loan_amount = request.POST.get('max_loan_amount', '').strip()
            address = request.POST.get('address', '').strip()

            # ✅ Field validations with friendly messages
            if not customer_name:
                return JsonResponse({'success': False, 'field': 'name',
                                     'error': "Please enter the customer's name."}, status=400)
            if not customer_code:
                return JsonResponse({'success': False, 'field': 'code',
                                     'error': "Please provide a unique customer code."}, status=400)
            if not mobile_number:
                return JsonResponse({'success': False, 'field': 'mobile_number',
                                     'error': "Please enter the customer's mobile number."}, status=400)
            if not line_id:
                return JsonResponse({'success': False, 'field': 'line',
                                     'error': "Please select a line."}, status=400)
            if not area_id:
                return JsonResponse({'success': False, 'field': 'area',
                                     'error': "Please select an area."}, status=400)
            if not status_value:
                return JsonResponse({'success': False, 'field': 'status',
                                     'error': "Please choose a status for the customer."}, status=400)
            if not maximum_loan_amount:
                return JsonResponse({'success': False, 'field': 'max_loan_amount',
                                     'error': "Please specify the maximum loan amount."}, status=400)
            if not address:
                return JsonResponse({'success': False, 'field': 'address',
                                     'error': "Please enter the customer's address."}, status=400)

            # ✅ Validate mobile number format
            if not mobile_number.isdigit() or len(mobile_number) != 10:
                return JsonResponse({'success': False, 'field': 'mobile_number',
                                     'error': "Mobile number must be 10 digits long."}, status=400)

            # ✅ Validate loan amount
            try:
                maximum_loan_amount = float(maximum_loan_amount)
                if maximum_loan_amount <= 0:
                    return JsonResponse({'success': False, 'field': 'max_loan_amount',
                                         'error': "Loan amount must be greater than 0."}, status=400)
            except ValueError:
                return JsonResponse({'success': False, 'field': 'max_loan_amount',
                                     'error': "Please enter a valid number for the loan amount."}, status=400)

            # ✅ Check related foreign keys
            line = get_object_or_404(Line, pk=line_id, created_by=user)
            area = get_object_or_404(Area, pk=area_id, created_by=user)

            # ✅ Ensure unique customer code
            if Customer.objects.filter(customer_code=customer_code, created_by=user).exists():
                return JsonResponse({'success': False, 'field': 'code',
                                     'error': f'The customer code "{customer_code}" is already in use.'}, status=409)

            # ✅ Create customer
            Customer.objects.create(
                customer_name=customer_name,
                customer_code=customer_code,
                mobile_number=mobile_number,
                line=line,
                area=area,
                status=status_value,
                maximum_loan_amount=maximum_loan_amount,
                address=address,
                created_by=request.user
            )

            return JsonResponse({'success': True, 'message': "🎉 Customer added successfully!"})

        except Exception as e:
            print(f"Add Customer Error: {e}")  # Debug log
            return JsonResponse({'success': False,
                                 'error': "Something went wrong while adding the customer. Please try again later."},
                                status=500)

    # ✅ GET request → render form
    lines = Line.objects.filter(created_by=user)
    areas = Area.objects.filter(created_by=user)

    return render(request, 'core/AddCustomer.html', {
        'lines': lines,
        'areas': areas
    })

@login_required
def add_expense(request):
    if request.method == 'POST':
        line_id = request.POST.get('line')
        name = request.POST.get('name', '').strip()
        amount = request.POST.get('amount', '').strip()
        date = request.POST.get('date', '').strip()
        comments = request.POST.get('comments', '').strip()

        # ✅ Required fields check
        if not all([line_id, name, amount, date]):
            error_msg = "⚠️ Please fill in all required fields (Line, Name, Amount, Date)."
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'success': False, 'error': error_msg}, status=400)
            messages.error(request, error_msg)
            return redirect('add_expense')

        # ✅ Validate amount
        try:
            amount = float(amount)
            if amount <= 0:
                raise ValueError
        except ValueError:
            error_msg = "❌ Please enter a valid positive amount."
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'success': False, 'field': 'amount', 'error': error_msg}, status=400)
            messages.error(request, error_msg)
            return redirect('add_expense')

        # ✅ Validate date
        try:
            expense_date = datetime.strptime(date, "%Y-%m-%d").date()
        except ValueError:
            error_msg = "❌ Please enter a valid date in YYYY-MM-DD format."
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'success': False, 'field': 'date', 'error': error_msg}, status=400)
            messages.error(request, error_msg)
            return redirect('add_expense')

        try:
            # ✅ Make sure the line belongs to the current user
            line_obj = Line.objects.get(id=line_id, created_by=request.user)

            # ✅ Create expense
            Expense.objects.create(
                line=line_obj,
                name=name,
                amount=amount,
                date=expense_date,
                comments=comments,
                created_by=request.user
            )

            success_msg = "🎉 Expense added successfully!"
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'success': True, 'message': success_msg}, status=201)
            messages.success(request, success_msg)
            return redirect('add_expense')

        except Line.DoesNotExist:
            error_msg = "❌ The selected line is invalid or does not belong to you."
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'success': False, 'field': 'line', 'error': error_msg}, status=400)
            messages.error(request, error_msg)
            return redirect('add_expense')

        except Exception as e:
            error_msg = "🚨 Something went wrong while adding the expense. Please try again."
            print(f"Add Expense Error: {e}")  # Debug log
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'success': False, 'error': error_msg}, status=500)
            messages.error(request, error_msg)
            return redirect('add_expense')

    # GET request → pass only lines created by this user
    user_lines = Line.objects.filter(created_by=request.user)
    return render(request, 'core/Expensive Add.html', {'lines': user_lines})


@login_required
def expense_list(request):
    user = request.user  # currently logged-in user

    # Get filter parameters from request
    from_date = request.GET.get('from_date', '')
    to_date = request.GET.get('to_date', '')
    line = request.GET.get('line', 'all')

    today = datetime.today().date()
    first_day = today.replace(day=1)

    # Default values
    from_date_obj, to_date_obj = first_day, today

    try:
        # ✅ Parse from_date safely
        if from_date:
            try:
                from_date_obj = datetime.strptime(from_date, '%Y-%m-%d').date()
            except ValueError:
                messages.error(request, "❌ Invalid 'From Date'. Please use YYYY-MM-DD format.")
                from_date_obj = first_day
        else:
            from_date = first_day.strftime('%Y-%m-%d')

        # ✅ Parse to_date safely
        if to_date:
            try:
                to_date_obj = datetime.strptime(to_date, '%Y-%m-%d').date()
            except ValueError:
                messages.error(request, "❌ Invalid 'To Date'. Please use YYYY-MM-DD format.")
                to_date_obj = today
        else:
            to_date = today.strftime('%Y-%m-%d')

        # ✅ Start with all expenses for this user
        expenses = Expense.objects.filter(created_by=user, date__range=(from_date_obj, to_date_obj))

        # ✅ Filter by line
        if line != 'all':
            if Line.objects.filter(id=line, created_by=user).exists():
                expenses = expenses.filter(line_id=line)
            else:
                messages.error(request, "❌ The selected line is invalid or does not belong to you.")
                line = 'all'

        # ✅ Calculate total
        total = sum(expense.amount for expense in expenses)

        # ✅ Fetch only the user's lines
        lines = Line.objects.filter(created_by=user)

        context = {
            'from_date': from_date_obj.strftime('%Y-%m-%d'),
            'to_date': to_date_obj.strftime('%Y-%m-%d'),
            'line': line,
            'lines': lines,
            'period_display': f"{from_date_obj.strftime('%d/%m/%Y')} - {to_date_obj.strftime('%d/%m/%Y')}",
            'total': total,
            'expenses': expenses,
        }

        return render(request, 'core/Expense.html', context)

    except Exception as e:
        # ✅ Catch any unexpected issues
        print(f"Expense List Error: {e}")  # Debugging log
        messages.error(request, "🚨 Something went wrong while loading expenses. Please try again.")
        return render(request, 'core/Expense.html', {
            'from_date': first_day.strftime('%Y-%m-%d'),
            'to_date': today.strftime('%Y-%m-%d'),
            'line': 'all',
            'lines': Line.objects.filter(created_by=user),
            'period_display': f"{first_day.strftime('%d/%m/%Y')} - {today.strftime('%d/%m/%Y')}",
            'total': 0,
            'expenses': [],
        })

# -------------------------------
# API VIEWS
# -------------------------------
class LineListCreateView(generics.ListCreateAPIView):
    """
    API to list all lines and create a new line
    """
    queryset = Line.objects.all()
    serializer_class = LineSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    def create(self, request, *args, **kwargs):
        try:
            # Debugging logs
            print(f"DEBUG: Incoming request data: {request.data}")
            print(f"DEBUG: Request user: {request.user}")
            print(f"DEBUG: Request method: {request.method}")

            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            return Response({
                'success': True,
                'message': 'Line created successfully',
                'data': serializer.data
            }, status=status.HTTP_201_CREATED, headers=headers)

        except Exception as e:
            print(f"DEBUG: Exception occurred: {str(e)}")
            import traceback
            print(f"DEBUG: Traceback: {traceback.format_exc()}")
            return Response({
                'success': False,
                'message': str(e),
                'error_type': type(e).__name__
            }, status=status.HTTP_400_BAD_REQUEST)


class LineDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    API to retrieve, update or delete a line
    """
    queryset = Line.objects.all()
    serializer_class = LineSerializer
    permission_classes = [permissions.IsAuthenticated]



# ------------------------
# LINE VIEWSET
# ------------------------
class LineViewSet(viewsets.ModelViewSet):
    queryset = Line.objects.all()
    serializer_class = LineSerializer


# ------------------------
# AREA VIEWSET
# ------------------------
class AreaViewSet(viewsets.ModelViewSet):
    queryset = Area.objects.all()
    serializer_class = AreaSerializer


# ------------------------
# CUSTOMER VIEWSET
# ------------------------
class CustomerViewSet(viewsets.ModelViewSet):
    queryset = Customer.objects.all()
    serializer_class = CustomerSerializer


# ------------------------
# LOAN VIEWSET
# ------------------------
# If using ViewSets
class LoanViewSet(viewsets.ModelViewSet):
    queryset = Loan.objects.all()
    serializer_class = LoanSerializer
    permission_classes = [AllowAny]
    
    def perform_create(self, serializer):
        # Automatically set the created_by field to the current user
        serializer.save(created_by=self.request.user)
    
    def create(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            self.perform_create(serializer)
            
            return Response({
                'success': True,
                'message': 'Loan created successfully',
                'data': serializer.data
            }, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({
                'success': False,
                'message': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    def get_queryset(self):
        # Only show loans created by the current user
        return Loan.objects.filter(created_by=self.request.user)



@login_required
def collection(request):
    """
    Filter page: select date, line, area.
    Includes user-friendly error handling.
    """
    user = request.user
    today = timezone.now().date()

    # Fetch lines & areas created by this user
    user_lines = Line.objects.filter(created_by=user)
    user_areas = Area.objects.filter(created_by=user)

    # Get query params
    selected_date = request.GET.get("date", "")
    selected_line = request.GET.get("line", "")
    selected_area = request.GET.get("area", "")

    # ✅ Validate date
    if selected_date:
        try:
            selected_date_obj = timezone.datetime.strptime(selected_date, "%Y-%m-%d").date()
        except ValueError:
            messages.error(request, "❌ Invalid date format. Please use YYYY-MM-DD.")
            selected_date_obj = today
            selected_date = today.strftime("%Y-%m-%d")
    else:
        selected_date_obj = today
        selected_date = today.strftime("%Y-%m-%d")

    # ✅ Validate line (only if user selected something)
    if selected_line:
        if not user_lines.filter(id=selected_line).exists():
            messages.error(request, "❌ The selected line is invalid or does not belong to you.")
            selected_line = None

    # ✅ Validate area (only if user selected something)
    if selected_area:
        if not user_areas.filter(id=selected_area).exists():
            messages.error(request, "❌ The selected area is invalid or does not belong to you.")
            selected_area = None

    context = {
        "user_lines": user_lines,
        "user_areas": user_areas,
        "today": today,
        "selected_date": selected_date,
        "selected_line": selected_line,
        "selected_area": selected_area,
    }
    return render(request, "core/collection.html", context)


@login_required
def collection_list(request):
    user = request.user
    today = timezone.now().date()

    customers = Customer.objects.select_related('loan', 'line', 'area').filter(created_by=user)

    # --- Filters ---
    selected_date = request.GET.get("date")
    selected_line = request.GET.get("line")
    selected_area = request.GET.get("area")

    # ✅ Validate date
    if selected_date:
        try:
            date_obj = datetime.strptime(selected_date, "%Y-%m-%d").date()
            customers = customers.filter(loan__next_due_date__lte=date_obj)
        except ValueError:
            messages.error(request, "❌ Invalid date format. Please use YYYY-MM-DD.")
            selected_date = None

    # ✅ Validate line
    if selected_line and selected_line != "all":
        if not Line.objects.filter(id=selected_line, created_by=user).exists():
            messages.error(request, "❌ The selected line is invalid or does not belong to you.")
            selected_line = None
        else:
            customers = customers.filter(line_id=selected_line)

    # ✅ Validate area
    if selected_area and selected_area != "all":
        if not Area.objects.filter(id=selected_area, created_by=user).exists():
            messages.error(request, "❌ The selected area is invalid or does not belong to you.")
            selected_area = None
        else:
            customers = customers.filter(area_id=selected_area)

    # --- Calculate dynamic overdue + adjusted installment ---
    for customer in customers:
        loan = getattr(customer, 'loan', None)
        if not loan:
            customer.adjusted_installment = 0
            customer.bad_loan_days = 0
            customer.bad_loan_amount = 0
            continue

        overdue_days = max(0, (today - loan.next_due_date).days) if loan.next_due_date else 0
        bad_percent_per_day = getattr(customer.line, 'bad_loan_days', 0) if customer.line else 0

        penalty_amount = loan.installment_amount * overdue_days * bad_percent_per_day / 100

        customer.adjusted_installment = round(loan.installment_amount + penalty_amount, 2)
        customer.bad_loan_days = overdue_days
        customer.bad_loan_amount = round(penalty_amount, 2)

    # ✅ Handle no results
    if not customers.exists():
        messages.info(request, "ℹ️ No customers found for the selected filters.")

    context = {
        "customers": customers.order_by('loan__next_due_date'),
        "selected_date": selected_date,
        "selected_line": selected_line,
        "selected_area": selected_area,
        "today": today,
    }
    return render(request, "core/collectionlist.html", context)

@login_required
@csrf_exempt
def collect_payment(request, customer_id):
    try:
        # ✅ Method check
        if request.method != "POST":
            return JsonResponse({
                "success": False,
                "message": "❌ Invalid request method. Please use POST."
            }, status=405)

        # ✅ Customer validation
        customer = get_object_or_404(Customer, id=customer_id, created_by=request.user)
        loan = getattr(customer, 'loan', None)

        if not loan:
            return JsonResponse({
                "success": False,
                "message": "❌ No active loan found for this customer."
            }, status=404)

        if loan.total_amount_to_pay <= 0 or loan.num_of_installments <= 0:
            return JsonResponse({
                "success": False,
                "message": "✅ Loan is already completed!"
            }, status=400)

        today = timezone.now().date()

        # --- Overdue calculation ---
        overdue_days = max(0, (today - loan.next_due_date).days) if loan.next_due_date else 0
        bad_percent_per_day = getattr(customer.line, 'bad_loan_days', 0) if customer.line else 0

        adjusted_installment = loan.installment_amount
        if overdue_days > 0:
            adjusted_installment += loan.installment_amount * overdue_days * bad_percent_per_day / 100

        # --- Deduct payment ---
        payment_amount = min(adjusted_installment, loan.total_amount_to_pay)
        if payment_amount <= 0:
            return JsonResponse({
                "success": False,
                "message": "⚠️ Payment amount is invalid. Nothing to collect."
            }, status=400)

        loan.total_amount_to_pay -= payment_amount
        loan.num_of_installments = max(loan.num_of_installments - 1, 0)

        # --- Record payment ---
        Payment.objects.create(
            customer=customer,
            user=request.user,
            due_date=loan.next_due_date or today,
            paid_on=today,
            amt_paid=payment_amount
        )

        # --- Update next due date ---
        is_completed = loan.total_amount_to_pay <= 0 or loan.num_of_installments <= 0
        if not is_completed:
            line_type_name = getattr(loan.line, 'line_type', '').lower() if loan.line else ''
            next_due = loan.next_due_date or today

            if line_type_name == 'daily':
                loan.next_due_date = next_due + timedelta(days=1)
            elif line_type_name == 'weekly':
                next_due += timedelta(days=7)
                if next_due.weekday() in [5, 6]:  # skip weekends
                    next_due += timedelta(days=(7 - next_due.weekday()))
                loan.next_due_date = next_due
            elif line_type_name == 'monthly':
                loan.next_due_date = next_due + relativedelta(months=1)
        else:
            loan.next_due_date = None
            loan.total_amount_to_pay = 0
            loan.num_of_installments = 0

        loan.save()

        # ✅ Success response
        return JsonResponse({
            "success": True,
            "message": "✅ Payment collected successfully!",
            "payment_collected": float(payment_amount),
            "remaining_amount": float(loan.total_amount_to_pay),
            "remaining_installments": loan.num_of_installments,
            "next_due_date": loan.next_due_date.strftime("%Y-%m-%d") if loan.next_due_date else None,
            "is_completed": is_completed,
            "adjusted_installment": round(float(adjusted_installment), 2),
            "bad_loan_days": overdue_days,
            "bad_loan_amount": round(adjusted_installment - loan.installment_amount, 2),
        }, status=200)

    except Customer.DoesNotExist:
        return JsonResponse({
            "success": False,
            "message": "❌ Customer not found or you don’t have permission."
        }, status=404)

    except Exception as e:
        # Friendly fallback for unexpected errors
        return JsonResponse({
            "success": False,
            "message": "⚠️ Something went wrong while collecting payment. Please try again."
        }, status=500)

def calculator(request):
    return render(request, "core/calculator.html")



#-----------------------
#Staff Panel
#-----------------------

@login_required
def staff_dashboard(request):
    user = request.user

    # ✅ Get all users created by this staff
    created_users = CustomUser.objects.filter(created_by_id=user.id)

    # 1. Active Agents
    active_agents_count = created_users.count()

    # 2. Loans Initiated
    loans_initiated_count = Loan.objects.filter(
        created_by_id__in=created_users.values("id")
    ).count()

    # 3. Total Expense
    total_expense_sum = Expense.objects.filter(
        created_by_id__in=created_users.values("id")
    ).aggregate(total=Sum("amount"))["total"] or 0

    # 4. Recent Activity
    recent_activities = created_users.order_by("-date_joined")[:5]
    activities_list = [f"{u.username} recently joined" for u in recent_activities]

    # 5. Users Joined Trend (group by month)
    users_per_month = (
        created_users.annotate(month=TruncMonth("date_joined"))
        .values("month")
        .annotate(count=Count("id"))
        .order_by("month")
    )

    labels = [u["month"].strftime("%b %Y") for u in users_per_month]
    data = [u["count"] for u in users_per_month]

    context = {
        "active_agents": active_agents_count,
        "loans_initiated": loans_initiated_count,
        "total_expense": total_expense_sum,
        "recent_activities": activities_list,
        "trend_labels": json.dumps(labels),
        "trend_data": json.dumps(data),
    }


    return render(request, "core/staff_dashboard.html", context)

@login_required
def staff_reports(request):
    return render(request, "core/staff_reports.html")

@login_required
def staff_user_management(request):
    # Restrict access to staff only
    if request.user.role != 'staff':
        messages.error(request, "❌ You do not have permission to access this page.")
        return redirect('/')

    # Get all users except superadmin and staff
    users = CustomUser.objects.exclude(role__in=['superadmin', 'staff']).order_by('-date_joined')

    # Handle no users case
    if not users.exists():
        messages.info(request, "ℹ️ No users found.")

    context = {
        'users': users
    }
    return render(request, 'core/staffuserManagement.html', context)


@login_required
@csrf_exempt
def delete_user(request, user_id):
    # ✅ Allow only DELETE requests
    if request.method != "DELETE":
        return JsonResponse({
            "success": False,
            "message": "❌ Method not allowed. Please use DELETE to remove a user."
        }, status=405)

    try:
        user = User.objects.get(id=user_id)

        # Optional: Prevent deleting superadmin or self
        if user.role == "superadmin":
            return JsonResponse({
                "success": False,
                "message": "❌ You cannot delete a superadmin user."
            }, status=403)
        if user == request.user:
            return JsonResponse({
                "success": False,
                "message": "⚠️ You cannot delete your own account."
            }, status=400)

        user.delete()
        return JsonResponse({
            "success": True,
            "message": "✅ User deleted successfully."
        })

    except User.DoesNotExist:
        return JsonResponse({
            "success": False,
            "message": "❌ User not found. It may have already been deleted."
        }, status=404)
    except Exception as e:
        return JsonResponse({
            "success": False,
            "message": "⚠️ Something went wrong while deleting the user. Please try again."
        }, status=500)

@login_required
@require_GET
def my_agents(request):
    agents = User.objects.filter(role="agent", created_by=request.user)

    data = [
        {
            "id": u.id,
            "username": u.username,
            "full_name": u.full_name,
            "email": u.email,
            "mobile_number": u.mobile_number,
            "is_active": u.is_active,
            "role": u.role,
        }
        for u in agents
    ]

    return JsonResponse(data, safe=False)

@login_required
@csrf_exempt
def agent_detail(request, pk):
    # Fetch the agent belonging to the current user
    agent = get_object_or_404(User, id=pk, created_by=request.user)

    if request.method == "GET":
        return JsonResponse({
            "id": agent.id,
            "username": agent.username,
            "full_name": agent.full_name or "N/A",
            "email": agent.email or "N/A",
            "mobile_number": agent.mobile_number or "N/A",
            "is_active": agent.is_active,
        })

    elif request.method in ["PUT", "PATCH"]:
        try:
            data = json.loads(request.body.decode("utf-8"))

            # Update basic fields if provided
            agent.full_name = data.get("full_name", agent.full_name)
            agent.username = data.get("username", agent.username)
            agent.email = data.get("email", agent.email)
            agent.mobile_number = data.get("mobile_number", agent.mobile_number)

            # Update status safely
            is_active = data.get("is_active")
            if is_active is not None:
                if isinstance(is_active, bool):
                    agent.is_active = is_active
                elif str(is_active).lower() in ["true", "1"]:
                    agent.is_active = True
                elif str(is_active).lower() in ["false", "0"]:
                    agent.is_active = False
                else:
                    return JsonResponse(
                        {"error": "Invalid value for status. Use true or false."},
                        status=400
                    )

            # Update password if provided
            new_password = data.get("password")
            if new_password:
                if len(new_password) < 6:
                    return JsonResponse(
                        {"error": "Password must be at least 6 characters long."},
                        status=400
                    )
                agent.password = make_password(new_password)

            agent.save()
            return JsonResponse({"message": "Agent updated successfully!"})

        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON. Please check your request data."}, status=400)
        except Exception as e:
            return JsonResponse({"error": "Something went wrong while updating the agent."}, status=400)

    # Method not allowed
    return JsonResponse({"error": "Method not allowed. Use GET, PUT, or PATCH."}, status=405)


@login_required
def payment_history(request):
    """
    Render the payments page.
    """
    return render(request, "core/payments.html")


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def user_payments(request):
    """
    Return payments made by agents created by the logged-in user.
    Always return a consistent response format.
    """
    try:
        # Get agents created by logged-in user
        agents = CustomUser.objects.filter(created_by=request.user.id)

        if not agents.exists():
            return Response(
                {"message": "No transaction made yet.", "data": []},
                status=status.HTTP_200_OK
            )

        agent_ids = agents.values_list("id", flat=True)

        # Get payments made by those agents
        payments = Payment.objects.filter(user_id__in=agent_ids).select_related("user", "customer")

        if not payments.exists():
            return Response(
                {"message": "No transaction made yet.", "data": []},
                status=status.HTTP_200_OK
            )

        serializer = PaymentSerializer(payments, many=True)
        return Response(
            {"message": "Payments fetched successfully.", "data": serializer.data},
            status=status.HTTP_200_OK
        )

    except Exception:
        return Response(
            {"error": "Something went wrong while fetching payments. Please try again later.", "data": []},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

@login_required
def profile_edit(request):
    return render(request, "core/profile_edit.html", {"user": request.user})

@api_view(["PUT"])
@permission_classes([IsAuthenticated])
def edit_profile_api(request):
    user = request.user
    data = request.data

    user.full_name = data.get("full_name", user.full_name)
    user.email = data.get("email", user.email)
    user.mobile_number = data.get("mobile_number", user.mobile_number)
    user.save()

    return Response({"message": "Profile updated successfully!"})
@login_required
def settings_view(request):
    return render(request, "core/staffSetting.html")

@login_required
def staff_changepassword(request):
    return render(request, "core/staffChangepassword.html")

@login_required
def line_report(request):
    from_date_str = request.GET.get("from_date")
    to_date_str = request.GET.get("to_date")

    report_entries = []
    total_principal = 0
    total_loans = 0

    if request.GET:
        if not from_date_str or not to_date_str:
            messages.error(request, "Please select both From and To dates.")
        else:
            try:
                from_date_parsed = date.fromisoformat(from_date_str)
                to_date_parsed = date.fromisoformat(to_date_str)

                if from_date_parsed > to_date_parsed:
                    messages.error(request, "From Date cannot be after To Date.")
                else:
                    # Step 1: Agents created by logged-in user
                    agents = CustomUser.objects.filter(created_by=request.user)

                    # Step 2: Lines created by those agents
                    lines = Line.objects.filter(created_by__in=agents)

                    # Step 3: Loans for those lines filtered by date
                    loans = Loan.objects.filter(
                        line__in=lines,
                        created_at__date__range=[from_date_parsed, to_date_parsed]
                    ).select_related('line')

                    if not loans.exists():
                        messages.warning(request, "No loans found for the selected date range.")
                    else:
                        # Step 4: Build report entries: one per loan per customer
                        for loan in loans:
                            customers = Customer.objects.filter(line=loan.line)
                            for customer in customers:
                                report_entries.append({
                                    "loan": loan,
                                    "customer": customer
                                })

                        # Step 5: Totals
                        total_principal = loans.aggregate(total=Sum("principal_amount"))["total"] or 0
                        total_loans = loans.count()
                        messages.success(request, "Report generated successfully.")

            except (ValueError, TypeError) as e:
                messages.error(request, f"Invalid date format. Please select valid dates. Error: {str(e)}")
            except Exception as e:
                messages.error(request, f"An unexpected error occurred: {str(e)}")

    context = {
        "report_entries": report_entries,
        "from_date": from_date_str,
        "to_date": to_date_str,
        "total_principal": total_principal,
        "total_loans": total_loans,
    }

    return render(request, "core/staff_LineReport.html", context)

@login_required
def line_report_download(request):
    from_date = request.GET.get("from_date")
    to_date = request.GET.get("to_date")

    # Check if dates are provided
    if not from_date or not to_date:
        messages.error(request, "Please select both From and To dates to download the report.")
        return redirect('line_report')  # redirect to your report page

    from_date_parsed = parse_date(from_date)
    to_date_parsed = parse_date(to_date)

    # Validate date parsing
    if not from_date_parsed or not to_date_parsed:
        messages.error(request, "Invalid date format. Please select valid dates.")
        return redirect('line_report')

    # Fetch loans and related customers
    agents = CustomUser.objects.filter(created_by=request.user)
    lines = Line.objects.filter(created_by__in=agents)
    loans = Loan.objects.filter(
        line__in=lines,
        created_at__date__range=[from_date_parsed, to_date_parsed]
    ).select_related('line')

    if not loans.exists():
        messages.warning(request, "No loans found for the selected date range.")
        return redirect('line_report')

    # Calculate totals
    total_loans = loans.count()
    total_principal = loans.aggregate(total=Sum('principal_amount'))['total'] or 0

    # Create CSV response
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="line_report_{from_date}_to_{to_date}.csv"'

    writer = csv.writer(response)
    # CSV headers
    writer.writerow(['Customer Name', 'Line Name', 'Issued Date', 'Loan Amount'])

    for loan in loans:
        customers = Customer.objects.filter(line=loan.line)
        for customer in customers:
            writer.writerow([
                customer.customer_name,
                loan.line.line_name,
                loan.created_at.strftime("%Y-%m-%d"),
                loan.principal_amount,
            ])

    # Add totals at the bottom
    writer.writerow([])
    writer.writerow(['', '', 'Total Loans', total_loans])
    writer.writerow(['', '', 'Total Loan Amount', total_principal])

    return response

@login_required
def area_report(request):
    from_date_str = request.GET.get("from_date")
    to_date_str = request.GET.get("to_date")

    report_entries = []
    total_principal = 0
    total_loans = 0

    if request.GET:
        if not from_date_str or not to_date_str:
            messages.error(request, "Please select both From and To dates.")
        else:
            try:
                from_date_parsed = date.fromisoformat(from_date_str)
                to_date_parsed = date.fromisoformat(to_date_str)

                if from_date_parsed > to_date_parsed:
                    messages.error(request, "From Date cannot be after To Date.")
                else:
                    # Step 1: Agents created by logged-in user
                    agents = CustomUser.objects.filter(created_by=request.user)

                    # Step 2: Areas created by those agents
                    areas = Area.objects.filter(created_by__in=agents)

                    # Step 3: Loans for those areas filtered by date
                    loans = Loan.objects.filter(
                        area__in=areas,
                        created_at__date__range=[from_date_parsed, to_date_parsed]
                    ).select_related('line', 'area')

                    if not loans.exists():
                        messages.warning(request, "No loans found for the selected date range.")
                    else:
                        # Step 4: Build report entries: one per loan per customer in that area
                        for loan in loans:
                            customers = Customer.objects.filter(area=loan.area)
                            for customer in customers:
                                report_entries.append({
                                    "area": loan.area,
                                    "loan": loan,
                                    "customer": customer
                                })

                        # Step 5: Calculate totals
                        total_principal = sum(entry['loan'].principal_amount for entry in report_entries)
                        total_loans = len(report_entries)
                        messages.success(request, "Report generated successfully.")

            except (ValueError, TypeError) as e:
                messages.error(request, f"Invalid date format. Please select valid dates. Error: {str(e)}")
            except Exception as e:
                messages.error(request, f"An unexpected error occurred: {str(e)}")

    context = {
        "report_entries": report_entries,
        "from_date": from_date_str,
        "to_date": to_date_str,
        "total_principal": total_principal,
        "total_loans": total_loans,
    }
    return render(request, "core/staff_AreaReport.html", context)


@login_required
def area_report_download(request):
    from_date = request.GET.get("from_date")
    to_date = request.GET.get("to_date")

    if not from_date or not to_date:
        return HttpResponse("Please provide From and To dates.", status=400)

    from_date_parsed = parse_date(from_date)
    to_date_parsed = parse_date(to_date)

    # Step 1: Get agents created by logged-in user
    agents = CustomUser.objects.filter(created_by=request.user)

    # Step 2: Get areas created by those agents
    areas = Area.objects.filter(created_by__in=agents)

    # Step 3: Get loans for those areas filtered by date
    loans = Loan.objects.filter(
        area__in=areas,
        created_at__date__range=[from_date_parsed, to_date_parsed]
    ).select_related('line', 'area')

    # Totals
    total_loans = loans.count()
    total_principal = loans.aggregate(total=Sum('principal_amount'))['total'] or 0

    # Create CSV response
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="area_report_{from_date}_to_{to_date}.csv"'

    writer = csv.writer(response)
    writer.writerow(['Customer Name', 'Area Name', 'Line Name', 'Issued Date', 'Loan Amount'])

    for loan in loans:
        customers = Customer.objects.filter(area=loan.area)
        for customer in customers:
            writer.writerow([
                customer.customer_name,
                loan.area.name,
                loan.line.line_name,
                loan.created_at.strftime("%Y-%m-%d"),
                loan.principal_amount,
            ])

    # Add totals
    writer.writerow([])
    writer.writerow(['', '', '', 'Total Loans', total_loans])
    writer.writerow(['', '', '', 'Total Loan Amount', total_principal])

    return response

@login_required
def expense_report(request):
    from_date_str = request.GET.get("from_date")
    to_date_str = request.GET.get("to_date")

    report_entries = []
    total_amount = 0
    total_expenses = 0

    if request.GET:
        if not from_date_str or not to_date_str:
            messages.error(request, "Please select both From and To dates.")
        else:
            try:
                from_date_parsed = date.fromisoformat(from_date_str)
                to_date_parsed = date.fromisoformat(to_date_str)

                if from_date_parsed > to_date_parsed:
                    messages.error(request, "From Date cannot be after To Date.")
                else:
                    # Step 1: Get agents created by logged-in user
                    agents = CustomUser.objects.filter(created_by=request.user)

                    # Step 2: Get expenses created by those agents
                    expenses = Expense.objects.filter(
                        created_by__in=agents,
                        date__range=[from_date_parsed, to_date_parsed]
                    )

                    if not expenses.exists():
                        messages.warning(request, "No expenses found for the selected date range.")
                    else:
                        # Step 3: Build report entries
                        for exp in expenses:
                            report_entries.append({
                                "agent_name": exp.created_by.get_full_name() or exp.created_by.username,
                                "name": exp.name,
                                "date": exp.date,
                                "amount": exp.amount,
                                "comments": exp.comments  # or description if your model has it
                            })

                        # Step 4: Totals
                        total_amount = sum(exp.amount for exp in expenses)
                        total_expenses = expenses.count()
                        messages.success(request, "Expense report generated successfully.")

            except ValueError as e:
                messages.error(request, f"Invalid date format. Please select valid dates. Error: {str(e)}")
            except Exception as e:
                messages.error(request, f"An unexpected error occurred: {str(e)}")

    context = {
        "report_entries": report_entries,
        "from_date": from_date_str,
        "to_date": to_date_str,
        "total_amount": total_amount,
        "total_expenses": total_expenses
    }

    return render(request, "core/staff_ExpenseReport.html", context)


@login_required
def expense_report_download(request):
    from_date_str = request.GET.get("from_date")
    to_date_str = request.GET.get("to_date")

    if not from_date_str or not to_date_str:
        messages.error(request, "Please select both From and To dates.")
        return HttpResponse("Error: From and To dates are required.", status=400)

    try:
        from_date_parsed = date.fromisoformat(from_date_str)
        to_date_parsed = date.fromisoformat(to_date_str)

        if from_date_parsed > to_date_parsed:
            messages.error(request, "From Date cannot be after To Date.")
            return HttpResponse("Error: From Date cannot be after To Date.", status=400)

        # Step 1: Get agents created by logged-in user
        agents = CustomUser.objects.filter(created_by=request.user)

        # Step 2: Get expenses created by those agents in the date range
        expenses = Expense.objects.filter(
            created_by__in=agents,
            date__range=[from_date_parsed, to_date_parsed]
        )

        if not expenses.exists():
            messages.warning(request, "No expenses found for the selected date range.")
            return HttpResponse("No expenses found for the selected date range.", status=404)

        # Step 3: Calculate totals
        total_amount = sum(exp.amount for exp in expenses)
        total_expenses = expenses.count()

        # Step 4: Create CSV response
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="expense_report_{from_date_str}_to_{to_date_str}.csv"'

        writer = csv.writer(response)
        # Header row
        writer.writerow(["Date", "Agent Name", "Expense Name", "Amount", "Comments"])

        # Data rows
        for exp in expenses:
            writer.writerow([
                exp.date.strftime("%Y-%m-%d"),
                exp.created_by.get_full_name() or exp.created_by.username,
                exp.name,
                exp.amount,
                getattr(exp, "comments", "")
            ])

        # Totals row
        writer.writerow([])
        writer.writerow(["","","", "Total_Expenses", total_expenses, ""])
        writer.writerow(["","","", "Total_Amount", total_amount, ""])

        return response

    except ValueError as e:
        messages.error(request, f"Invalid date format. Please select valid dates. Error: {str(e)}")
        return HttpResponse(f"Error: Invalid date format. {str(e)}", status=400)

    except Exception as e:
        messages.error(request, f"An unexpected error occurred: {str(e)}")
        return HttpResponse(f"Error: An unexpected error occurred. {str(e)}", status=500)

















































































#----------------
#  SUPERUSER
#---------------

@login_required
def superadmin_dashboard(request):
    # Restrict access
    if request.user.role != 'superadmin':
        return redirect('/')

    # ---------- Stats ----------
    total_loans_count = Loan.objects.count()

    # Total loan amount from Customers (max loan amount field)
    total_loan_amount = Customer.objects.aggregate(
        total=Sum('maximum_loan_amount')
    )['total'] or 0

    total_active_users = CustomUser.objects.filter(
        is_active=True
    ).exclude(role__in=['superadmin', 'staff']).count()

    total_areas = Area.objects.count()

    # ---------- Activities ----------
    activities = []

    # Recent agents
    recent_agents = CustomUser.objects.filter(
        role='agent'
    ).order_by('-date_joined')[:5]
    for agent in recent_agents:
        activities.append({
            'type': 'success',
            'message': f"New agent joined: {agent.full_name}",
            'timestamp': agent.date_joined
        })

    # Recent customers
    recent_customers = Customer.objects.order_by('-created_at')[:5]
    for customer in recent_customers:
        activities.append({
            'type': 'info',
            'message': f"New customer added: {customer.customer_name}",
            'timestamp': customer.created_at
        })

    # Recent loans → fetch related customer via OneToOne
    recent_loans = Loan.objects.order_by('-created_at')[:5]
    for loan in recent_loans:
        # Customer linked to this loan (via OneToOne)
        customer = getattr(loan, "customer", None)
        customer_name = customer.customer_name if customer else "Unknown"
        activities.append({
            'type': 'warning',
            'message': f"New loan initiated for: {customer_name}",
            'timestamp': loan.created_at
        })

    # Sort activities (latest first)
    activities.sort(key=lambda x: x['timestamp'], reverse=True)
    activities = activities[:5]

    # ---------- Loan Graph ----------
    loan_per_line = (
        Loan.objects.values('line__line_name')
        .annotate(total=Sum('principal_amount'))
        .order_by('line__line_name')
    )
    loan_labels = [item['line__line_name'] for item in loan_per_line]
    loan_data = [float(item['total'] or 0) for item in loan_per_line]

    # ---------- User Trend Graph (last 7 days) ----------
    today = now().date()
    last_7_days = [today - timedelta(days=i) for i in range(6, -1, -1)]

    user_labels = [d.strftime("%b %d") for d in last_7_days]
    user_data = []
    for day in last_7_days:
        count = CustomUser.objects.filter(
            date_joined__date=day
        ).exclude(role__in=['superadmin', 'staff']).count()
        user_data.append(count)

    context = {
        'total_loans_count': total_loans_count,
        'total_loan_amount': total_loan_amount,
        'total_active_users': total_active_users,
        'total_areas': total_areas,
        'activities': activities,
        'graph_labels': json.dumps(loan_labels),
        'graph_data': json.dumps(loan_data),
        'user_graph_labels': json.dumps(user_labels),
        'user_graph_data': json.dumps(user_data),
    }

    return render(request, 'core/superadmin_dashboard.html', context)




def enter_username(request):
    return render(request, 'core/forget_password.html')


# Step 1: Send code to user's email based on username
def send_code(request):
    if request.method != 'POST':
        return JsonResponse({'success': False, 'error': 'Invalid request method'})

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Invalid JSON'})

    username = data.get('username')
    if not username:
        return JsonResponse({'success': False, 'error': 'Username is required'})

    try:
        user = User.objects.get(username=username)
        code = random.randint(100000, 999999)

        # Save code and email in session
        request.session['reset_code'] = code
        request.session['reset_email'] = user.email
        request.session['reset_username'] = username

        # Email subject and sender
        subject = "🔐 Vasool App - Password Reset Request"
        to = [user.email]
        from_email = settings.DEFAULT_FROM_EMAIL

        # Plain-text version (fallback)
        text_content = f"""
Hello {username},

We received a request to reset the password for your Vasool App account.

Your OTP is: {code}

This OTP is valid for 15 minutes. Please do not share it with anyone.

If you did not request this, you can safely ignore this email.

For assistance, contact our support team at support@vasoolapp.com

© 2025 Vasool App. All rights reserved.
"""

        # HTML version
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="UTF-8">
          <title>Password Reset</title>
          <style>
            body {{
              font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
              background-color: #f5f5f5;
              color: #333;
              line-height: 1.6;
              padding: 0;
              margin: 0;
            }}
            .container {{
              max-width: 600px;
              margin: 50px auto;
              background: #ffffff;
              padding: 30px;
              border-radius: 8px;
              box-shadow: 0 4px 10px rgba(0,0,0,0.1);
            }}
            .header {{
              text-align: center;
              margin-bottom: 20px;
            }}
            .header h1 {{
              color: #4361ee;
              font-size: 24px;
              margin: 0;
            }}
            .content {{
              font-size: 16px;
            }}
            .otp {{
              display: block;
              text-align: center;
              font-size: 28px;
              font-weight: bold;
              background: #e0e7ff;
              margin: 20px 0;
              padding: 15px;
              border-radius: 6px;
              letter-spacing: 3px;
            }}
            .footer {{
              font-size: 12px;
              color: #777;
              text-align: center;
              margin-top: 30px;
            }}
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>Vasool App Password Reset</h1>
            </div>
            <div class="content">
              <p>Hello <strong>{username}</strong>,</p>
              <p>We received a request to reset the password for your Vasool App account associated with this email.</p>
              
              <p class="otp">{code}</p>
              
              <p>This OTP is valid for <strong>15 minutes</strong>. Please do not share it with anyone. If you did not request a password reset, you can safely ignore this email.</p>
            
              <p>For assistance, contact our support team at 
                 <a href="mailto:support@vasoolapp.com">support@vasoolapp.com</a>.
              </p>
              
              <div class="footer">
                &copy; 2025 Vasool App. All rights reserved.
              </div>
            </div>
          </div>
        </body>
        </html>
        """

        # Send the email with both plain text + HTML
        email = EmailMultiAlternatives(subject, text_content, from_email, to)
        email.attach_alternative(html_content, "text/html")
        email.send(fail_silently=False)

        return JsonResponse({'success': True})

    except User.DoesNotExist:
        return JsonResponse({'success': False, 'error': 'Username not found'})


# Step 2: Verify code
def verify_code(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        code = data.get('code')

        if not code:
            return JsonResponse({'success': False, 'error': 'Code is required'})

        if str(code) == str(request.session.get('reset_code')):
            return JsonResponse({'success': True})
        else:
            return JsonResponse({'success': False, 'error': 'Invalid code'})

    return JsonResponse({'success': False, 'error': 'Invalid request method'})


# Step 3: Reset password
def reset_password(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        password = data.get('password')
        email = request.session.get('reset_email')

        if not password:
            return JsonResponse({'success': False, 'error': 'Password is required'})

        try:
            user = User.objects.get(email=email)
            user.set_password(password)
            user.save()

            # Clear session
            request.session.pop('reset_code', None)
            request.session.pop('reset_email', None)
            request.session.pop('reset_username', None)

            return JsonResponse({'success': True})
        except User.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'User not found'})

    return JsonResponse({'success': False, 'error': 'Invalid request method'})








