from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils.translation import gettext_lazy as _

from .managers import CustomUserManager


class Project(models.Model):
    name = models.CharField(max_length=180)

    objects = models.Manager()

    def __str__(self):
        return self.name


class CustomUser(AbstractUser):
    is_developer = models.BooleanField(_("Developer"), default=True)
    is_projectmanager = models.BooleanField(_("Project Manager"), default=False)
    project = models.ForeignKey(Project, on_delete=models.CASCADE, null=True)
    USERNAME_FIELD = "username"

    objects = CustomUserManager()

    def __str__(self):
        return self.username


class Task(models.Model):
    name = models.CharField(max_length=180)
    description = models.TextField(default="None", blank=True)
    completed = models.BooleanField(default=False, blank=True)
    project = models.ForeignKey(Project, on_delete=models.CASCADE)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, null=True)
    objects = models.Manager()

    def __str__(self):
        return self.name



