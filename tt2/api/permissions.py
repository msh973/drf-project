from rest_framework.permissions import BasePermission


class IsDeveloperUser(BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_developer)


class IsProjectManagerUser(BasePermission):
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_projectmanager)
