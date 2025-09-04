from django.http import HttpResponse
from django.urls import path, include
from django.contrib.auth import views as auth_views
from rest_framework_simplejwt.views import (
    TokenRefreshView,
    TokenVerifyView
)
from rest_framework.routers import DefaultRouter

from . import views
from .custom_auth import CustomTokenObtainPairView
from .views import (
    CustomUserListView, PaymentDetail, PaymentList, login_view, settings, area_settings, change_password, subscription_page,
    support, license, mysettings, ProfileUpdateView,
    LineListCreateView, LineDetailView,
    LineViewSet, AreaViewSet, CustomerViewSet, LoanViewSet,
    add_customer_page, user_settings
    
)
from django.shortcuts import render


# Router for ViewSets
router = DefaultRouter()
router.register(r'lines', LineViewSet)
router.register(r'areas', AreaViewSet)
router.register(r'customers', CustomerViewSet)
router.register(r'loans', LoanViewSet)

def home(request):
    return render(request, 'login.html') 


urlpatterns = [
    # Auth & User
    path('', home, name='home'),
    path("cron-task/", views.cron_task, name="cron_task"),
    path('register/', views.register_view, name='register'),
    path('login/', login_view, name='login'),
    path('signout/', views.signout, name='signout'),
    path("calculator/", views.calculator, name="calculator"),

    # Settings
    path('settings/', user_settings, name='settings'),
    path('settings/LineSettings.html', views.line_settings, name='line_settings'),
    path('settings/LineAddCollection.html', views.add_line, name='line_add_collection'),
    path('settings/mySettings.html', mysettings, name='mysettings_alt'),
    path('settings/SignOut.html', views.signout, name='signout_alt'),
    path('mysettings/', mysettings, name='mysettings'),

    # Area
    path('add_area/', views.add_area, name='add_area'),
    path('area_settings/', area_settings, name='area_settings'),
    path('delete/<int:area_id>/', views.delete_area, name='delete_area'),

    # Customer
    path('add-customer/', views.add_customer, name='add_customer'),
    path("add-customer/page/", add_customer_page, name="create_customer"),

    # Expenses
    path('add-expense/', views.add_expense, name='add_expense'),
    path('expense_list/', views.expense_list, name='expense_list'),

    # Collections
    path('collection/', views.collection, name='collection'),
    path('collection_list/', views.collection_list, name='collection_list'),
    path('collect_payment/<int:customer_id>/', views.collect_payment, name='collect_payment'),

    # Misc
    path('change_password/', change_password, name='change_password'),
    path('support/', support, name='support'),
    path('license/', license, name='license'),
    path('languagae/', views.languagae, name='languagae'),

    #superadmin urls
    # path('superadmin-dashboard/', views.superadmin_dashboard, name='superadmin_dashboard'),
    path('payments/', views.subscription_page , name='payments'),
    path('api/users/', CustomUserListView.as_view(), name='user-list'),
    path('api/users/<int:pk>/', views.UserDetailView.as_view(), name='user-detail'),
    path('superadmin/users/', views.user_management, name='user_management'),
    path('api/users/<int:user_id>/edit/', views.edit_user, name='edit_user'),
    path('api/users/<int:user_id>/delete/', views.delete_user, name='delete_user'),
    path('api/loans/', views.loan_list, name='loan-list-api'),
    path('loan-management/', views.loan_management_page, name='loan-management-page'),
    path('api/loans/<int:loan_id>/', views.delete_loan, name='delete_loan'),
    path('transaction/', views.payments_page, name='payments_page'),
    path('api/transaction/', views.PaymentList.as_view(), name='payments_details'),  
    path('api/transaction/<int:pk>/', views.PaymentDetail.as_view(), name='payment-detail'),

    #forget password
    path('forgot-password/', views.enter_username, name='enter_username'),
    path('send-code/', views.send_code, name='send_code'),
    path('verify-code/', views.verify_code, name='verify_code'),
    path('reset-password/', views.reset_password, name='reset_password'),

    #StaffPage
    path("staff-dashboard/", views.staff_user_management, name="staff_userManagement"),

    # API endpoints
    path('send-code/', views.send_code, name='send_code'),
    path('verify-code/', views.verify_code, name='verify_code'),
    path('reset-password/', views.reset_password, name='reset_password'),

    # REST API endpoints for models
    path('api/customers/', CustomerViewSet.as_view({'get': 'list', 'post': 'create'}), name='customer-list'),
    path('api/customers/<int:pk>/', CustomerViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='customer-detail'),

    path('api/expenses/', views.ExpenseViewSet.as_view({'get': 'list', 'post': 'create'}), name='expense-list'),
    path('api/expenses/<int:pk>/', views.ExpenseViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='expense-detail'),

    path('api/areas/', AreaViewSet.as_view({'get': 'list', 'post': 'create'}), name='area-list'),
    path('api/areas/<int:pk>/', AreaViewSet.as_view({'get': 'retrieve', 'put': 'update', 'delete': 'destroy'}), name='area-detail'),

    # JWT Authentication
    path('api/token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/verify/', TokenVerifyView.as_view(), name='token_verify'),

    # Include router URLs
    path('api/', include(router.urls)),
]
