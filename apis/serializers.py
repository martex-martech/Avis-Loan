from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .models import Customer, Expense, Area, CustomUser, Payment

User = get_user_model()

class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'full_name', 'mobile_number','expiry_date', 'password', 'password2')
        extra_kwargs = {
            'full_name': {'required': True},
            'email': {'required': True},
        }

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        return attrs

    def create(self, validated_data):
        user = User.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            full_name=validated_data['full_name'],
            mobile_number=validated_data.get('mobile_number', '')
        )
        user.set_password(validated_data['password'])
        user.save()
        return user

    def update(self, instance, validated_data):
        instance.full_name = validated_data.get('full_name', instance.full_name)
        instance.mobile_number = validated_data.get('mobile_number', instance.mobile_number)
        instance.email = validated_data.get('email', instance.email)
        instance.save()
        return instance

        
        # Update Profile fields if profile exists
        if hasattr(instance, 'profile'):
            profile = instance.profile
            profile.mobile_number = profile_data.get('mobile_number', profile.mobile_number)
            profile.save()
        
        return instance

class UserProfileUpdateSerializer(serializers.ModelSerializer):
    mobile_number = serializers.CharField(required=False, allow_blank=True)

    class Meta:
        model = User
        fields = ['full_name', 'email', 'mobile_number']
        extra_kwargs = {
            'email': {'required': True},
            'full_name': {'required': True},
        }

    def validate_email(self, value):
        try:
            validate_email(value)
        except ValidationError:
            raise serializers.ValidationError("Enter a valid email address.")
        
        if User.objects.filter(email=value).exclude(pk=self.instance.pk).exists():
            raise serializers.ValidationError("This email is already in use.")
        return value

# Customer Serializer
class CustomerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Customer
        fields = '__all__'
        
    def create(self, validated_data):
        return Customer.objects.create(**validated_data)
        
    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance

# Expense Serializer
class ExpenseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Expense
        fields = '__all__'
        
    def create(self, validated_data):
        return Expense.objects.create(**validated_data)
        
    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance

# Area Serializer
class AreaSerializer(serializers.ModelSerializer):
    class Meta:
        model = Area
        fields = '__all__'
        
    def create(self, validated_data):
        return Area.objects.create(**validated_data)
        
    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance
from rest_framework import serializers
from .models import Line
from django.contrib.auth import get_user_model

User = get_user_model()

class LineSerializer(serializers.ModelSerializer):
    created_by = serializers.SlugRelatedField(
        slug_field='username',
        queryset=User.objects.all(),
        required=False
    )
    line_id = serializers.IntegerField(source='id', read_only=True)

    class Meta:
        model = Line
        fields = [
            'line_id',
            'line_name',
            'line_type',
            'interest_per_hundred',
            'bill_amt_per_100',
            'num_of_installments',
            'bad_loan_days',
            'created_by',
            'created_at',
        ]
        read_only_fields = ['line_id', 'created_at']
        extra_kwargs = {
            'line_name': {
                'required': True,
                'help_text': 'Name of the credit line (required)'
            },
            'line_type': {
                'required': True,
                'help_text': 'Type of credit line: PL (Personal Loan), BL (Business Loan), CL (Credit Line), ML (Mortgage Loan), or AL (Auto Loan)'
            },
            'interest_per_hundred': {
                'required': True,
                'help_text': 'Interest rate per 100 units (must be between 0.01 and 999.99)'
            },
            'bill_amt_per_100': {
                'required': True,
                'help_text': 'Bill amount per 100 units (must be greater than 0)'
            },
            'num_of_installments': {
                'required': True,
                'help_text': 'Number of installments (must be greater than 0)'
            },
            'bad_loan_days': {
                'required': True,
                'help_text': 'Number of days after which loan is considered bad (must be greater than 0)'
            }
        }
    
    def validate_interest_per_hundred(self, value):
        if value is None:
            raise serializers.ValidationError("Interest per hundred is required")
        try:
            value = float(value)
            if value <= 0 or value > 9999999.99:  # Updated to match new model constraint
                raise serializers.ValidationError("Interest per 100 must be between 0.01 and 9999999.99")
            return value
        except (ValueError, TypeError):
            raise serializers.ValidationError("Interest per hundred must be a valid number")
    
    def validate_bill_amt_per_100(self, value):
        if value is None:
            raise serializers.ValidationError("Bill amount per 100 is required")
        try:
            value = float(value)
            if value <= 0:
                raise serializers.ValidationError("Bill amount per 100 must be greater than 0")
            return value
        except (ValueError, TypeError):
            raise serializers.ValidationError("Bill amount per 100 must be a valid number")
    
    def validate_num_of_installments(self, value):
        if value is None:
            raise serializers.ValidationError("Number of installments is required")
        try:
            value = int(value)
            if value <= 0:
                raise serializers.ValidationError("Number of installments must be greater than 0")
            return value
        except (ValueError, TypeError):
            raise serializers.ValidationError("Number of installments must be a valid integer")
    
    def validate_bad_loan_days(self, value):
        if value is None:
            raise serializers.ValidationError("Bad loan days is required")
        try:
            value = int(value)
            if value <= 0:
                raise serializers.ValidationError("Bad loan days must be greater than 0")
            return value
        except (ValueError, TypeError):
            raise serializers.ValidationError("Bad loan days must be a valid integer")
    
    def validate_line_type(self, value):
        valid_types = [choice[0] for choice in Line.LINE_TYPES]
        if value not in valid_types:
            raise serializers.ValidationError(
                f"Invalid line type. Must be one of: {', '.join([f'{choice[0]} ({choice[1]})' for choice in Line.LINE_TYPES])}"
            )
        return value
    
    def validate_line_name(self, value):
        if not value or not str(value).strip():
            raise serializers.ValidationError("Line name is required and cannot be empty")
        return str(value).strip()
    
    def create(self, validated_data):
        # Set the created_by user to the current user if not provided
        if 'created_by' not in validated_data:
            validated_data['created_by'] = self.context['request'].user
        return super().create(validated_data)
    
    def to_representation(self, instance):
        representation = super().to_representation(instance)
        # Add human-readable line type
        representation['line_type_display'] = instance.get_line_type_display()
        return representation
from rest_framework import serializers
from .models import Line, Area, Customer, Loan



# ------------------------
# LOAN SERIALIZER
# ------------------------
class LoanSerializer(serializers.ModelSerializer):
    customer_name = serializers.CharField(source='customer.customer_name', read_only=True)

    class Meta:
        model = Loan
        fields = '__all__'
        read_only_fields = (
            'total_interest_amount',
            'installment_amount',
            'total_amount_to_pay',
            'num_of_installments',
            'next_due_date',
            'created_at'
        )


# ------------------------
# CUSTOMER SERIALIZER
# ------------------------
class CustomerSerializer(serializers.ModelSerializer):
    loans = LoanSerializer(many=True, read_only=True)

    class Meta:
        model = Customer
        fields = '__all__'


class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User   # from get_user_model()
        fields = '__all__'   # fetch everything from the DB

class PaymentSerializer(serializers.ModelSerializer):
    customer_name = serializers.CharField(source='customer.customer_name', read_only=True)
    agent_name = serializers.CharField(source='user.username', read_only=True)
    date = serializers.DateField(source='paid_on', read_only=True)

    class Meta:
        model = Payment
        fields = ['payment_id', 'date', 'customer_name', 'agent_name', 'amt_paid']
    