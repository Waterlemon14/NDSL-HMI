from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import User

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    # The fields to be used in displaying the User model.
    # These columns will appear in the list view.
    list_display = ('uin', 'firstName', 'lastName', 'is_admin')
    
    # Filter options on the right sidebar
    list_filter = ('is_admin', 'is_active')
    
    # The fields to be used in the "Edit User" page
    fieldsets = (
        (None, {'fields': ('uin', 'password')}),
        ('Personal info', {'fields': ('firstName', 'lastName')}),
        ('Permissions', {'fields': ('is_admin', 'is_active')}),
    )

    # This allows you to add a new user via the admin
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('uin', 'firstName', 'lastName', 'is_admin', 'is_active'),
        }),
    )
    
    search_fields = ('uin', 'lastName')
    ordering = ('uin',)
    filter_horizontal = ()

    # Since we are using set_unusable_password(), 
    # we make the password field read-only in the admin.
    readonly_fields = ('password',)