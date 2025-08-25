from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import path, include
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)
from apis import views

urlpatterns = [
    # Admin panel
    path('admin/', admin.site.urls),

    # Home page and app URLs
    path('', views.login_view, name='home'),
    path('', include('apis.urls')),

    # API endpoints
    path('api/', include([
        # Authentication endpoints
        path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
        path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
        path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),

        # User registration
        path('register/', views.register_view_api, name='register-api'),

        # Include other app-specific API endpoints here
        # path('users/', include('your_app.urls')),
    ])),
]
