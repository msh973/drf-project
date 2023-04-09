from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from .forms import CustomUserCreationForm, CustomUserChangeForm
from .models import CustomUser, Project, Task

admin.site.register(Project)
admin.site.register(Task)



class CustomUserAdmin(UserAdmin):
    add_form = CustomUserCreationForm
    form = CustomUserChangeForm
    model = CustomUser
    list_display = ("username", "is_staff", "is_active", "is_developer", "is_projectmanager",)
    list_filter = ("username", "is_staff", "is_active", "is_developer", "is_projectmanager",)
    fieldsets = (
        (None, {"fields": ("username", "password")}),
        ("Permissions",
         {"fields": ("is_staff", "is_active", "is_developer", "is_projectmanager", "groups", "user_permissions")}),
    )
    add_fieldsets = (
        (None, {
            "classes": ("wide",),
            "fields": (
                "username", "password1", "password2", "is_staff",
                "is_active", "is_developer", "is_projectmanager", "groups", "user_permissions"
            )}
         ),
    )
    search_fields = ("username",)
    ordering = ("username",)


admin.site.register(CustomUser, CustomUserAdmin)
