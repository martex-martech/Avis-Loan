import random
from django.shortcuts import render, redirect
from django.contrib.auth import get_user_model
from django.contrib import messages
from rest_framework import status
from datetime import date, timedelta
from django.utils import timezone
from django.http import JsonResponse, HttpResponseNotAllowed
import json
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

from django.contrib.auth import get_user_model
from django.contrib import messages
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.shortcuts import redirect, render
import re

User = get_user_model()

def register_view(request):
    if request.method == 'POST':
        try:
            data = request.POST

            username = data.get('username')
            email = data.get('email')
            password = data.get('password1')
            password2 = data.get('password2')
            full_name = data.get('full_name')
            mobile_number = data.get('mobile_number')
        
            if not all([username, email, password, password2, full_name, mobile_number]):
                return JsonResponse({'error': 'All fields are required.'}, status=400)
            
            if password != password2:
                return JsonResponse({'error': 'Passwords do not match.'}, status=400)
            
            try:
                validate_email(email)
            except ValidationError:
                return JsonResponse({'error': 'Enter a valid email address.'}, status=400)
            
            if not re.fullmatch(r'^\d{10}$', mobile_number):
                return JsonResponse({'error': 'Enter a valid 10-digit mobile number.'}, status=400)
            
            if User.objects.filter(username=username).exists():
                return JsonResponse({'error': 'Username already exists.'}, status=409)
            
            if User.objects.filter(email=email).exists():
                return JsonResponse({'error': 'Email already registered.'}, status=409)
            
            if len(password) < 8 or not re.search(r'[A-Za-z]', password) or not re.search(r'[0-9]', password):
                return JsonResponse({'error': 'Password must be at least 8 characters long and contain both letters and numbers.'}, status=400)
            
            # Create user (role defaults to 'agent')
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password,
                full_name=full_name,
                mobile_number=mobile_number
            )
            
            return JsonResponse({'message': 'Registration successful!'}, status=200)

        except Exception as e:
            return JsonResponse({'error': f'An unexpected error occurred: {str(e)}'}, status=500)
    
    return render(request, 'core/register.html')

@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def register_view_api(request):
    """
    API endpoint for user registration
    """
    from rest_framework import status
    
    username = request.data.get('username')
    email = request.data.get('email')
    password = request.data.get('password')
    
    if not all([username, email, password]):
        return Response({
            'success': False,
            'message': 'Username, email, and password are required'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    if User.objects.filter(username=username).exists():
        return Response({
            'success': False,
            'message': 'Username already exists'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    if User.objects.filter(email=email).exists():
        return Response({
            'success': False,
            'message': 'Email already registered'
        }, status=status.HTTP_400_BAD_REQUEST)
    
    user = User.objects.create_user(
        username=username,
        email=email,
        password=password
    )
    
    return Response({
        'success': True,
        'message': 'User registered successfully',
        'user_id': user.id
    }, status=status.HTTP_201_CREATED)

from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.shortcuts import render, redirect


def login_view(request):
    if request.method == 'POST' and request.headers.get('x-requested-with') == 'XMLHttpRequest':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '').strip()

        # Basic validation
        if not username:
            return JsonResponse({'success': False, 'error': 'Username is required.'})
        if not password:
            return JsonResponse({'success': False, 'error': 'Password is required.'})
        if len(password) < 6:
            return JsonResponse({'success': False, 'error': 'Password must be at least 6 characters long.'})

        user = authenticate(request, username=username, password=password)

        if user:
            login(request, user)
            # Return role for frontend redirect
            return JsonResponse({'success': True, 'role': user.role})
        else:
            return JsonResponse({'success': False, 'error': 'Invalid username or password.'})

    return render(request, 'core/login.html')

def user_settings(request):
    """
    Display user settings page
    """
    return render(request, 'core/settingspages/Settings.html')

@login_required
def area_settings(request):
    """
    Display area settings page
    """
    areas = Area.objects.filter(created_by=request.user)  # Only areas created by this user
    return render(request, 'core/settingspages/AreaSettings.html', {'areas': areas, 'user': request.user})

from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.shortcuts import render, redirect

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import update_session_auth_hash
from django.contrib import messages
import re

@login_required
def change_password(request):
    """Handle password change for logged-in user via AJAX"""
    if request.method == 'POST':
        try:
            # Get data from the POST request
            old_password = request.POST.get('oldPassword')
            new_password = request.POST.get('newPassword')
            confirm_password = request.POST.get('confirmPassword')

            # 1. Empty fields check
            if not all([old_password, new_password, confirm_password]):
                return JsonResponse({'error': '⚠️ All fields are required.'}, status=400)

            # 2. New password match check
            if new_password != confirm_password:
                return JsonResponse({'error': '❌ New passwords do not match.'}, status=400)
                
            # 3. Old password verification
            if not request.user.check_password(old_password):
                return JsonResponse({'error': '❌ Current password is incorrect.'}, status=400)

            # 4. Prevent reuse of old password
            if old_password == new_password:
                return JsonResponse({'error': '❌ New password cannot be the same as the old password.'}, status=400)

            # 5. Core password validation (same as your original logic)
            if len(new_password) < 8:
                return JsonResponse({'error': '❌ New password must be at least 8 characters long.'}, status=400)
            if not re.search(r'[A-Z]', new_password):
                return JsonResponse({'error': '❌ New password must contain at least one uppercase letter.'}, status=400)
            if not re.search(r'[a-z]', new_password):
                return JsonResponse({'error': '❌ New password must contain at least one lowercase letter.'}, status=400)
            if not re.search(r'[0-9]', new_password):
                return JsonResponse({'error': '❌ New password must contain at least one digit.'}, status=400)
            if not re.search(r'[!@#$%^&*()_+=\-`~\[\]{};:\'\"<>?,.\/\\|]', new_password):
                return JsonResponse({'error': '❌ New password must contain at least one special character.'}, status=400)

            # 6. Save new password securely (hashed)
            request.user.set_password(new_password)
            request.user.save()

            # Keep user logged in after password change
            update_session_auth_hash(request, request.user)

            # Return a JSON success response instead of rendering a template
            return JsonResponse({'message': '✅ Password changed successfully!'})

        except Exception as e:
            # Catch any other unexpected errors and return a JSON error
            print(f"Password change error: {e}") # Optional: Log the error
            return JsonResponse({'error': 'An unexpected error occurred. Please try again.'}, status=500)

    # For GET requests, render the page as normal
    return render(request, 'core/settingspages/ChangePassword.html')

def support(request):
    """
    Display support page
    """
    return render(request, 'core/settingspages/support.html')

from django.shortcuts import render, get_object_or_404
from apis.models import CustomUser
from django.contrib.auth.decorators import login_required

@login_required
def license(request):
    user = request.user
    
    
    context = {
        'username': user.username,
        'annual_amount': '₹999',
        'valid_until': user.expiry_date if hasattr(user, 'expiry_date') else 'N/A'
    }
    
    return render(request, 'core/settingspages/license.html', context)

@csrf_exempt
@login_required
def mysettings(request):
    """
    GET: Render HTML page (normal request) or return JSON (AJAX request).
    PUT: Update user details in DB.
    """
    if request.method == "GET":
        # If AJAX request, return JSON profile data
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            try:
                user = CustomUser.objects.get(pk=request.user.pk)
                return JsonResponse({
                    "username": user.username,
                    "email": user.email,
                    "mobile_number": user.mobile_number
                })
            except CustomUser.DoesNotExist:
                return JsonResponse({"detail": "User not found"}, status=404)
        # Otherwise render the settings page
        return render(request, 'core/settingspages/mySettings.html')

    elif request.method == "PUT":
        try:
            data = json.loads(request.body.decode("utf-8"))

            # Get current user
            user = CustomUser.objects.get(pk=request.user.pk)

            # Update only provided fields
            if "username" in data:
                user.username = data["username"]
            if "email" in data:
                user.email = data["email"]
            if "mobile_number" in data:
                user.mobile_number = data["mobile_number"]

            user.save()

            return JsonResponse({"message": "Profile updated successfully!"}, status=200)

        except CustomUser.DoesNotExist:
            return JsonResponse({"detail": "User not found"}, status=404)
        except Exception as e:
            return JsonResponse({"detail": str(e)}, status=400)

    return JsonResponse({"detail": "Invalid request method"}, status=405)

def signout(request):
    """
    Handle user logout
    """
    from django.contrib.auth import logout
    logout(request)
    messages.success(request, 'You have been successfully logged out.')
    return redirect('login')

from django.shortcuts import get_object_or_404

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from .models import Customer, Line, Area

@login_required
def add_customer(request):
    user = request.user

    if request.method == 'POST':
        try:
            customer_name = request.POST.get('name')
            customer_code = request.POST.get('code')
            mobile_number = request.POST.get('mobile_number')
            line_id = request.POST.get('line')
            area_id = request.POST.get('area')
            status_value = request.POST.get('status')
            maximum_loan_amount = request.POST.get('max_loan_amount')
            address = request.POST.get('address')

            # Validate required fields
            if not all([customer_name, customer_code, mobile_number, line_id, area_id, status_value, maximum_loan_amount, address]):
                return JsonResponse({'error': 'All fields are required.'}, status=400)

            # Get related FK objects (only those created by this user)
            line = get_object_or_404(Line, pk=line_id, created_by=user)
            area = get_object_or_404(Area, pk=area_id, created_by=user)

            # Check for existing customer code
            if Customer.objects.filter(customer_code=customer_code, created_by=user).exists():
                return JsonResponse({'error': f'Customer code "{customer_code}" already exists.'}, status=409)

            # Create customer
            Customer.objects.create(
                customer_name=customer_name,
                customer_code=customer_code,
                mobile_number=mobile_number,
                line=line,
                area=area,
                status=status_value,
                maximum_loan_amount=float(maximum_loan_amount),
                address=address,
                created_by=request.user
            )

            # Return a JSON success response
            return JsonResponse({'message': 'Customer added successfully!'})

        except Exception as e:
            # Handle any exceptions and return a JSON error response
            return JsonResponse({'error': f'An error occurred: {str(e)}'}, status=500)

    # For a GET request, render the initial form page
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
        name = request.POST.get('name')
        amount = request.POST.get('amount')
        date = request.POST.get('date')
        comments = request.POST.get('comments')
        
        if not all([line_id, name, amount, date]):
            return JsonResponse({'error': 'All fields are required.'}, status=400)
        
        try:
            # Make sure the line belongs to the current user
            line_obj = Line.objects.get(id=line_id, created_by=request.user)
            
            expense = Expense.objects.create(
                line=line_obj,
                name=name,
                amount=float(amount),
                date=date,
                comments=comments,
                created_by=request.user
            )
            return JsonResponse({'message': 'Expense added successfully!'}, status=200)
        except Line.DoesNotExist:
            return JsonResponse({'error': 'Selected line is invalid.'}, status=400)
        except Exception as e:
            return JsonResponse({'error': f'Error adding expense: {str(e)}'}, status=500)
    
    # GET request → pass only lines created by this user
    user_lines = Line.objects.filter(created_by=request.user)
    return render(request, 'core/Expensive Add.html', {'lines': user_lines})

@login_required
def add_area(request):
    if request.method == 'POST':
        area_name = request.POST.get('area_name')
        if area_name:
            try:
                # Add the logged-in user as created_by
                Area.objects.create(
                    name=area_name,
                    created_by=request.user
                )

                # If AJAX request, return JSON
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({'message': 'Area added successfully!'}, status=201)

                # Normal form submission
                messages.success(request, 'Area added successfully!')
                return redirect('area_settings')

            except Exception as e:
                error_msg = str(e)
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({'error': error_msg}, status=400)
                messages.error(request, 'Area with this name already exists!')
        else:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'error': 'Area name cannot be empty!'}, status=400)
            messages.error(request, 'Area name cannot be empty!')

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

from datetime import datetime
from django.shortcuts import render
from .models import Expense, Line

from django.shortcuts import render
from datetime import datetime
from .models import Expense, Line

def expense_list(request):
    user = request.user  # currently logged-in user

    # Get filter parameters from request
    from_date = request.GET.get('from_date', '')
    to_date = request.GET.get('to_date', '')
    line = request.GET.get('line', 'all')
    
    # Set default dates (first day of current month to today)
    today = datetime.today().date()
    first_day = today.replace(day=1)
    
    # Start with all expenses for this user
    expenses = Expense.objects.filter(created_by=user)

    # Filter by date
    if from_date:
        from_date_obj = datetime.strptime(from_date, '%Y-%m-%d').date()
        expenses = expenses.filter(date__gte=from_date_obj)
    else:
        from_date_obj = first_day
        from_date = from_date_obj.strftime('%Y-%m-%d')
    
    if to_date:
        to_date_obj = datetime.strptime(to_date, '%Y-%m-%d').date()
        expenses = expenses.filter(date__lte=to_date_obj)
    else:
        to_date_obj = today
        to_date = to_date_obj.strftime('%Y-%m-%d')
    
    # Filter by line if selected
    if line != 'all':
        expenses = expenses.filter(line_id=line)  # use line_id for foreign key filtering
    
    # Calculate total
    total = sum(expense.amount for expense in expenses)
    
    # Fetch lines created by this user for the dropdown
    lines = Line.objects.filter(created_by=user)
    
    context = {
        'from_date': from_date,
        'to_date': to_date,
        'line': line,
        'lines': lines,  # pass user-specific lines
        'period_display': f"{from_date_obj.strftime('%d/%m/%Y')} - {to_date_obj.strftime('%d/%m/%Y')}",
        'total': total,
        'expenses': expenses,
    }
    
    return render(request, 'core/Expense.html', context)

def languagae(request):
    """
    Display my settings page
    """
    return render(request, 'core/settingspages/LanguageSettings.html')



def add_line(request):
    return render(request, 'core/LineAddCollection.html')
    


from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from .models import Line
from .serializers import LineSerializer


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


# -------------------------------
# TEMPLATE VIEW
# -------------------------------
@login_required
def line_settings(request):
    """
    Display the Line Settings HTML page
    """
    user_lines = Line.objects.filter(created_by=request.user)
    return render(request, "core/LineSettings.html", {"lines": user_lines})

# Customer/views.py
from django.shortcuts import render
from rest_framework import viewsets
from .models import Line, Area, Customer, Loan
from .serializers import LineSerializer, AreaSerializer, CustomerSerializer, LoanSerializer


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

def add_customer_page(request):
    return render(request, "core/AddCustomer.html")

def collection(request):
    """
    Filter page: select date, line, area.
    """
    user = request.user
    today = timezone.now().date()

    user_lines = Line.objects.filter(created_by=user)
    user_areas = Area.objects.filter(created_by=user)

    context = {
        "user_lines": user_lines,
        "user_areas": user_areas,
        "today": today,
        "selected_date": request.GET.get("date", today),
        "selected_line": request.GET.get("line"),
        "selected_area": request.GET.get("area"),
    }
    return render(request, "core/collection.html", context)


def collection_list(request):
    user = request.user
    today = timezone.now().date()

    customers = Customer.objects.select_related('loan', 'line', 'area').filter(created_by=user)

    # --- Filters ---
    selected_date = request.GET.get("date")
    selected_line = request.GET.get("line")
    selected_area = request.GET.get("area")

    if selected_date:
        try:
            date_obj = datetime.strptime(selected_date, "%Y-%m-%d").date()
            customers = customers.filter(loan__next_due_date__lte=date_obj)
        except ValueError:
            pass

    if selected_line and selected_line != "all":
        customers = customers.filter(line_id=selected_line)

    if selected_area and selected_area != "all":
        customers = customers.filter(area_id=selected_area)

    # --- Calculate dynamic overdue + adjusted installment ---
    for customer in customers:
        loan = getattr(customer, 'loan', None)
        if not loan:
            customer.adjusted_installment = 0
            customer.bad_loan_days = 0
            customer.bad_loan_amount = 0
            continue

        if loan.next_due_date:
            overdue_days = max(0, (today - loan.next_due_date).days)
        else:
            overdue_days = 0

        # Get line-specific daily bad loan percentage
        bad_percent_per_day = getattr(customer.line, 'bad_loan_days', 0) if customer.line else 0

        # Calculate total penalty amount
        penalty_amount = loan.installment_amount * overdue_days * bad_percent_per_day / 100

        # Adjusted installment
        customer.adjusted_installment = round(loan.installment_amount + penalty_amount, 2)
        customer.bad_loan_days = overdue_days
        customer.bad_loan_amount = round(penalty_amount, 2)

    context = {
        "customers": customers.order_by('loan__next_due_date'),
        "selected_date": selected_date,
        "today": today,
    }
    return render(request, "core/collectionlist.html", context)

@csrf_exempt
def collect_payment(request, customer_id):
    try:
        if request.method != "POST":
            return JsonResponse({"success": False, "message": "Invalid request method."})

        customer = get_object_or_404(Customer, id=customer_id)
        loan = getattr(customer, 'loan', None)

        if not loan or loan.total_amount_to_pay <= 0:
            return JsonResponse({"success": False, "message": "Loan already completed or not found."})

        today = timezone.now().date()

        # --- Overdue calculation ---
        overdue_days = max(0, (today - loan.next_due_date).days) if loan.next_due_date else 0
        bad_percent_per_day = getattr(customer.line, 'bad_loan_days', 0) if customer.line else 0

        # Adjusted installment including overdue penalty
        adjusted_installment = loan.installment_amount
        if overdue_days > 0:
            adjusted_installment += loan.installment_amount * overdue_days * bad_percent_per_day / 100

        # --- Deduct payment ---
        payment_amount = min(adjusted_installment, loan.total_amount_to_pay)
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

        # --- Update next due date if loan is not completed ---
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
            # Loan completed: set next_due_date to None
            loan.next_due_date = None
            loan.total_amount_to_pay = 0
            loan.num_of_installments = 0

        loan.save()

        return JsonResponse({
            "success": True,
            "payment_collected": float(payment_amount),
            "remaining_amount": float(loan.total_amount_to_pay),
            "remaining_installments": loan.num_of_installments,
            "next_due_date": loan.next_due_date.strftime("%Y-%m-%d") if loan.next_due_date else None,
            "is_completed": is_completed,
            "adjusted_installment": round(float(adjusted_installment), 2),
            "bad_loan_days": overdue_days,
            "bad_loan_amount": round(adjusted_installment - loan.installment_amount, 2),
        })

    except Exception as e:
        return JsonResponse({"success": False, "message": str(e)})
    
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

    # Total loan amount from Customers
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

    # Recent loans
    recent_loans = Loan.objects.order_by('-created_at')[:5]
    for loan in recent_loans:
        customer_name = getattr(loan.customer, 'customer_name', 'Unknown')
        activities.append({
            'type': 'warning',
            'message': f"New loan initiated for: {customer_name}",
            'timestamp': loan.created_at
        })

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
    from django.utils.timezone import now, timedelta
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


@login_required
def subscription_page(request):
    # Only superadmin can access
    if request.user.role != 'superadmin':
        return redirect('/')

    users = CustomUser.objects.exclude(role__in=['superadmin', 'staff']).order_by('-date_joined')

    subscriptions = []
    from django.utils.timezone import now
    today = now().date()

    for user in users:
        expiry = getattr(user, 'expiry_date', None)
        status = "Active"
        if expiry and expiry < today:
            status = "Expired"
        elif not expiry:
            status = "No Plan"

        subscriptions.append({
            'name': user.full_name,
            'username': user.username,
            'email': user.email,
            'role': user.role,
            'expiry': expiry.strftime("%Y-%m-%d") if expiry else "—",
            'status': status,
        })

    context = {
        'subscriptions': subscriptions
    }
    return render(request, 'core/subscription.html', context)

class CustomUserListView(generics.ListAPIView):
    queryset = User.objects.all()
    serializer_class = CustomUserSerializer

class UserDetailView(APIView):

    def get(self, request, pk):
        try:
            user = CustomUser.objects.get(pk=pk)
        except CustomUser.DoesNotExist:
            return Response({"detail": "User not found"}, status=status.HTTP_404_NOT_FOUND)
        
        serializer = CustomUserSerializer(user)
        return Response(serializer.data)

    def patch(self, request, pk):
        try:
            user = CustomUser.objects.get(pk=pk)
        except CustomUser.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)
        
        serializer = CustomUserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    
@login_required
def user_management(request):
    # Restrict access to superadmin only
    if request.user.role != 'superadmin':
        return redirect('/')
    
    # Get all users except superadmin and staff
    users = CustomUser.objects.exclude(role__in=['superadmin', 'staff']).order_by('-date_joined')
    
    context = {
        'users': users
    }
    return render(request, 'core/user_management.html', context)

@csrf_exempt
def edit_user(request, user_id):
    if request.method != "PUT":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        user = User.objects.get(id=user_id)
    except User.DoesNotExist:
        return JsonResponse({"error": "User not found"}, status=404)

    try:
        data = json.loads(request.body)

        # Update password if provided
        if "password" in data and data["password"]:
            user.set_password(data["password"])

        # Update other fields
        user.full_name = data.get("full_name", user.full_name)
        user.username = data.get("username", user.username)
        user.email = data.get("email", user.email)
        user.mobile_number = data.get("mobile_number", user.mobile_number)
        if "is_active" in data:
            user.is_active = data["is_active"]

        user.save()
        return JsonResponse({
            "id": user.id,
            "full_name": user.full_name,
            "username": user.username,
            "email": user.email,
            "mobile_number": user.mobile_number,
            "is_active": user.is_active
        })
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=400)


@csrf_exempt
def delete_user(request, user_id):
    if request.method != "DELETE":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    try:
        user = User.objects.get(id=user_id)
        user.delete()
        return JsonResponse({"success": True, "message": "User deleted successfully"})
    except User.DoesNotExist:
        return JsonResponse({"error": "User not found"}, status=404)

# views.py
from django.shortcuts import render
from django.http import JsonResponse
from .models import Loan

# API endpoint (your existing code)
def loan_list(request):
    loans = Loan.objects.select_related('customer').all()
    data = []

    for loan in loans:
        customer = loan.customer
        # Determine status based on next_due_date
        status = "completed" if loan.next_due_date is None else "not_completed"
        data.append({
            "id": loan.id,
            "amount": loan.total_amount_to_pay,
            "date": loan.next_due_date.strftime("%Y-%m-%d") if loan.next_due_date else "-",
            "status": status,
            "customer": {
                "id": customer.id,
                "name": getattr(customer, "customer_name", "Unknown"),
                "email": getattr(customer, "email", ""),
            }
        })

    return JsonResponse(data, safe=False)



# Page view to render the template
def loan_management_page(request):
    return render(request, 'core/loan_management.html')


def delete_loan(request, loan_id):
    if request.method == "DELETE":
        loan = get_object_or_404(Loan, id=loan_id)
        loan.delete()
        return JsonResponse({"success": True, "message": f"Loan {loan_id} deleted"})
    else:
        return HttpResponseNotAllowed(["DELETE"])
    
@login_required
def payments_page(request):
    return render(request, 'core/payments.html') 

class PaymentList(APIView):
    def get(self, request):
        payments = Payment.objects.all()
        serializer = PaymentSerializer(payments, many=True)
        return Response(serializer.data)

class PaymentDetail(APIView):
    def get(self, request, pk):
        try:
            payment = Payment.objects.get(pk=pk)
        except Payment.DoesNotExist:
            return Response({'error': 'Payment not found'}, status=404)
        serializer = PaymentSerializer(payment)
        return Response(serializer.data)
    
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

        # Email content
        subject = "🔐 Vasool App - Password Reset Request"
        to = [user.email]
        from_email = settings.DEFAULT_FROM_EMAIL

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
            .button {{
              display: inline-block;
              background-color: #4361ee;
              color: #ffffff !important;
              text-decoration: none;
              padding: 12px 20px;
              border-radius: 6px;
              margin-top: 20px;
              font-weight: bold;
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
            
              
              <p>For assistance, contact our support team at <a href="mailto:support@vasoolapp.com">support@vasoolapp.com</a>.</p>
              
              <div class="footer">
                &copy; 2025 Vasool App. All rights reserved.
              </div>
            </div>
          </div>
        </body>
        </html>
        """

        # Send the email
        email = EmailMultiAlternatives(subject, "Your email client does not support HTML.", from_email, to)
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

def calculator(request):
    return render(request, "core/calculator.html")


def cron_task(request):
    return JsonResponse({"status": "ok"})