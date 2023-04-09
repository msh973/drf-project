from django.shortcuts import render, get_object_or_404

from django.views.generic import ListView
from .models import Task


class TasksList(ListView):

    def get_queryset(self):
        return Task.objects.filter(project=self.kwargs.get("pj"))

