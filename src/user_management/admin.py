from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as AuthUserAdmin
from django.utils.translation import gettext as _

from user_management.models import Admin, Customer, CustomToken, CustomUser


# Get the custom user model
UserModel = get_user_model()


# Define the CustomUser admin configuration
class CustomUserAdmin(AuthUserAdmin):
    list_display = ('email', 'name', 'phone', 'user_type', 'is_active', 'is_staff')
    list_filter = ('is_active', 'is_staff', 'user_type')
    search_fields = ['email', 'name', 'phone']
    ordering = ['email']

    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (
            _('Personal info'),
            {'fields': ('name', 'phone', 'company', 'address', 'user_type')},
        ),
        (_('Permissions'), {'fields': ('is_active', 'is_staff')}),
        (_('Important dates'), {'fields': ('last_login',)}),
    )

    add_fieldsets = (
        (
            None,
            {
                'classes': ('wide',),
                'fields': (
                    'email',
                    'password1',
                    'password2',
                    'name',
                    'phone',
                    'user_type',
                ),
            },
        ),
    )

    filter_horizontal = ()  # Remove groups field from filter_horizontal

    exclude = ('timestamp',)  # Exclude the timestamp field

    def has_add_permission(self, request):
        return True


# Register the CustomUser model with the custom admin configuration
@admin.register(CustomUser)
class CustomUserAdminModel(CustomUserAdmin):
    pass


# Register the Admin proxy model with the custom admin configuration
@admin.register(Admin)
class AdminAdmin(CustomUserAdmin):
    list_display = ('email', 'name', 'phone', 'is_active', 'is_staff')
    list_filter = ('is_active', 'is_staff')
    search_fields = ['email', 'name']

    def has_add_permission(self, request):
        return False  # Disable add permission for Admins


# Register the Customer proxy model with the custom admin configuration
@admin.register(Customer)
class CustomerAdmin(CustomUserAdmin):
    list_display = ('email', 'name', 'phone', 'user_type', 'is_active')
    list_filter = ('is_active', 'user_type')
    search_fields = ['email', 'name', 'phone']

    def has_add_permission(self, request):
        return True  # Enable add permission for Customers

@admin.register(CustomToken)
class CustomTokenAdmin(admin.ModelAdmin):
    pass