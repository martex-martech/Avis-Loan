from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework.response import Response
from rest_framework import status


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """
    Custom token serializer that includes additional user information
    """
    def validate(self, attrs):
        data = super().validate(attrs)
        
        # Add extra user info to response
        data.update({
            'user': {
                'id': self.user.id,
                'username': self.user.username,
                'email': self.user.email,
                'first_name': self.user.first_name,
                'last_name': self.user.last_name,
                'full_name': f"{self.user.first_name} {self.user.last_name}".strip()
            }
        })
        
        return data


class CustomTokenObtainPairView(TokenObtainPairView):
    """
    Custom token view with better error handling
    """
    serializer_class = CustomTokenObtainPairSerializer
    
    def post(self, request, *args, **kwargs):
        try:
            response = super().post(request, *args, **kwargs)
            return Response({
                'status': 'success',
                'message': 'Login successful',
                'data': response.data
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'status': 'error',
                'message': 'Invalid credentials',
                'error': str(e)
            }, status=status.HTTP_401_UNAUTHORIZED)
