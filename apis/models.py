from datetime import timedelta, date
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.core.validators import RegexValidator
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.db.models.signals import post_save
from django.dispatch import receiver


# ------------------------
# CUSTOM USER MODEL
# ------------------------
class CustomUser(AbstractUser):
    ROLE_CHOICES = [
        ('agent', 'Agent'),
        ('staff', 'Staff'),
        ('superadmin', 'Superadmin'),
    ]

    mobile_number = models.CharField(
        max_length=15,
        validators=[RegexValidator(r'^\+?1?\d{9,15}$', "Enter a valid mobile number.")],
        blank=True,
        null=True
    )
    full_name = models.CharField(max_length=255)
    expiry_date = models.DateField(null=True, blank=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='agent')  # new field

    def save(self, *args, **kwargs):
        if not self.pk and self.date_joined:
            self.expiry_date = self.date_joined.date() + timedelta(days=30)
        super().save(*args, **kwargs)

    @property
    def days_remaining(self):
        if not self.expiry_date:
            return None
        today = timezone.now().date()
        remaining = (self.expiry_date - today).days
        if remaining <= 0 and self.is_active:
            self.is_active = False
            self.save(update_fields=["is_active"])
            return 0
        return max(remaining, 0)


# ------------------------
# EXPENSE MODEL
# ------------------------
from django.contrib.auth import get_user_model

User = get_user_model()

class Expense(models.Model):
    line = models.ForeignKey(
        'Line',  # Link to the Line model
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='expenses'
    )
    name = models.CharField(max_length=100)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    date = models.DateField()
    comments = models.TextField(blank=True)
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, related_name='created_expenses'
    )

    def __str__(self):
        if self.created_by:
            return f"{self.name} ({self.created_by.username})"
        return self.name


# ------------------------
# AREA MODEL
# ------------------------
from django.contrib.auth import get_user_model

User = get_user_model()

class Area(models.Model):
    name = models.CharField(max_length=255, unique=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return self.name



# ------------------------
# LINE MODEL
# ------------------------
User = get_user_model()

class Line(models.Model):

    LINE_TYPES = [
        ('Daily', 'Daily'),
        ('Weekly', 'Weekly'),
        ('Monthly', 'Monthly'),
    ]
        
    line_name = models.CharField(max_length=100, null=True, blank=True)
    line_type = models.CharField(max_length=20, choices=LINE_TYPES)
    interest_per_hundred = models.DecimalField(max_digits=10, decimal_places=2)
    bill_amt_per_100 = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    num_of_installments = models.PositiveIntegerField()
    bad_loan_days = models.PositiveIntegerField()
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, related_name='created_lines'
    )
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['-created_at']



# ------------------------
# CUSTOMER MODEL
# ------------------------
class Customer(models.Model):
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive'),
    ]

    customer_name = models.CharField(max_length=255, blank=True, null=True)
    customer_code = models.CharField(max_length=50, unique=True, blank=True, null=True)
    mobile_number = models.CharField(max_length=15, blank=True, null=True)
    line = models.ForeignKey(Line, on_delete=models.SET_NULL, null=True, blank=True)
    area = models.ForeignKey(Area, on_delete=models.SET_NULL, null=True, blank=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='active')
    maximum_loan_amount = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    address = models.TextField(blank=True, null=True)
    created_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, related_name='created_customers'
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.customer_name or 'No Name'} ({self.customer_code or 'No Code'})"


# ------------------------
# LOAN MODEL
# ------------------------
class Loan(models.Model):
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE, related_name="loans")
    line = models.ForeignKey(Line, on_delete=models.CASCADE)
    area = models.ForeignKey('Area', on_delete=models.SET_NULL, null=True, blank=True)  # <-- new field
    principal_amount = models.DecimalField(max_digits=10, decimal_places=2)
    total_interest_amount = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    installment_amount = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    total_amount_to_pay = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    num_of_installments = models.IntegerField(null=True, blank=True)
    next_due_date = models.DateField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Loan for {self.customer.customer_name} - {self.principal_amount}"


# ------------------------
# SIGNAL: CREATE LOAN WHEN CUSTOMER IS CREATED
# ------------------------
@receiver(post_save, sender=Customer)
def create_initial_loan(sender, instance, created, **kwargs):
    if created and instance.maximum_loan_amount and instance.line:
        L = float(instance.maximum_loan_amount)
        I100 = float(instance.line.interest_per_hundred or 0)
        B100 = float(instance.line.bill_amt_per_100 or 0)
        N = int(instance.line.num_of_installments or 0)

        # Loan Calculations
        total_interest_amount = (L / 100) * I100 * N
        installment_amount = (L / 100) * B100
        total_amount_to_pay = installment_amount * N

        # Due Date Calculation
        days_map = {
            'daily': 1,
            'weekly': 7,
            'monthly': 30
        }
        next_due = None
        if instance.line.line_type:
            next_due = timezone.now().date() + timedelta(days=days_map.get(instance.line.line_type.lower(), 0))

        # Create Loan Entry including customer area
        Loan.objects.create(
            customer=instance,
            line=instance.line,
            area=instance.area,  # <-- add the area here
            principal_amount=L,
            total_interest_amount=total_interest_amount,
            installment_amount=installment_amount,
            total_amount_to_pay=total_amount_to_pay,
            num_of_installments=N,
            next_due_date=next_due
        )

class Payment(models.Model):
    payment_id = models.AutoField(primary_key=True)
    customer = models.ForeignKey(Customer, on_delete=models.CASCADE)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    due_date = models.DateField()
    paid_on = models.DateField(null=True, blank=True)
    amt_paid = models.DecimalField(max_digits=10, decimal_places=2)

    def __str__(self):
        return f"{self.customer} - {self.amt_paid}"
