from django.http import HttpResponse
from django.urls import path, include
from django.contrib.auth import views as auth_views
from rest_framework_simplejwt.views import ( TokenRefreshView, TokenVerifyView)
from rest_framework.routers import DefaultRouter
from . import views
from .custom_auth import CustomTokenObtainPairView
from .views import (
    agent_settings, login_view, area_settings, change_password,
    support, license, mysettings, ProfileUpdateView,
    LineListCreateView, LineDetailView,
    LineViewSet, AreaViewSet, CustomerViewSet, LoanViewSet,
    
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
    # Auth
    path('', home, name='home'),
    path("cron-task/", views.cron_task, name="cron_task"),
    path('register/', views.register_view, name='register'),
    path('login/', login_view, name='login'),

    #forget password
    path('forgot-password/', views.enter_username, name='enter_username'),
    path('send-code/', views.send_code, name='send_code'),
    path('verify-code/', views.verify_code, name='verify_code'),
    path('reset-password/', views.reset_password, name='reset_password'),

    # Agent Settings
    path('settings/', agent_settings, name='settings'),
    path('support/', support, name='support'),
    path('license/', license, name='license'),
    path('settings/LineSettings.html', views.line_settings, name='line_settings'),
    path('settings/LineAddCollection.html', views.add_line, name='line_add_collection'),
    path('area_settings/', area_settings, name='area_settings'),
    path('add_area/', views.add_area, name='add_area'),
    path('delete/<int:area_id>/', views.delete_area, name='delete_area'),
    path('settings/agentProfileEdit.html', mysettings, name='mysettings_alt'),
    path('mysettings/', mysettings, name='mysettings'),
    path('languagae/', views.languagae, name='languagae'),
    path('change_password/', change_password, name='change_password'),
    path('settings/SignOut.html', views.signout, name='signout_alt'),
    path('signout/', views.signout, name='signout'),

    # Agent Customer
    path('add-customer/', views.add_customer, name='add_customer'),

    # Expenses
    path('add-expense/', views.add_expense, name='add_expense'),
    path('expense_list/', views.expense_list, name='expense_list'),

    # Collections
    path('collection/', views.collection, name='collection'),
    path('collection_list/', views.collection_list, name='collection_list'),
    path('collect_payment/<int:customer_id>/', views.collect_payment, name='collect_payment'),
    path("calculator/", views.calculator, name="calculator"),

    # Staff Panel
    path("staff-dashboard/", views.staff_dashboard, name="staff_dashboard"),
    path("user-management/", views.staff_user_management, name="staff_userManagement"),
    path('api/users/<int:user_id>/delete/', views.delete_user, name='delete_user'),
    path("api/my-agents/", views.my_agents, name="my_agents"),
    path("api/my-agents/<int:pk>/", views.agent_detail, name="agent_detail"),
    path("payments/", views.payment_history, name="payments"),
    path("api/payments/", views.user_payments, name="user-payments"),
    path('staff/reports/', views.staff_reports, name='staff_reports'),
    path("reports/line/", views.line_report, name="line_report"),
    path('reports/line/download/', views.line_report_download, name='line_report_download'),
    path('reports/area/', views.area_report, name='area_report'),
    path('reports/area/download/', views.area_report_download, name='area_report_download'),
    path('reports/expense/', views.expense_report, name='expense_report'),
    path('reports/expense/download/', views.expense_report_download, name='expense_report_download'),
    path("profile/edit/", views.profile_edit, name="profile_edit"),
    path("api/edit-profile/", views.edit_profile_api, name="edit-profile-api"),
    path("staff/settings/", views.settings_view, name="staff_settings"),
    path("staff/changePassword/", views.staff_changepassword, name="staff_changepassword"),
    path('api/users/<int:user_id>/change-password/', views.change_password, name='change_password'),

    # Superadmin Panel
    path('superadmin-dashboard/', views.superadmin_dashboard, name='superadmin_dashboard'),

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
