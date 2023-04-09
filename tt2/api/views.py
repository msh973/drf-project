from django.shortcuts import render
from tt2app.models import CustomUser, Task, Project
from rest_framework.generics import ListAPIView, ListCreateAPIView, CreateAPIView, UpdateAPIView
from .serializers import TaskSerializer, DeveloperTaskSerializer, ProjectManagerTaskSerializer, UserSerializer, ProjectSerializer, AssigneeSerializer
from rest_framework import permissions
from django.http import HttpRequest
from .permissions import IsProjectManagerUser, IsDeveloperUser


class TasksList(ListAPIView):
    serializer_class = TaskSerializer

    def get_queryset(self):
        tasks = Task.objects.filter(project=self.request.user.project)
        return tasks


class UserTasksList(ListAPIView):
    serializer_class = TaskSerializer
    permission_classes = (IsProjectManagerUser,)

    def get_queryset(self):
        tasks = Task.objects.filter(project=self.request.user.project, user=self.request.user)
        return tasks


class CreateTaskDeveloper(CreateAPIView):
    serializer_class = DeveloperTaskSerializer
    permission_classes = (IsDeveloperUser,)

    def perform_create(self, serializer):
        instance = serializer.save(user=self.request.user, project=self.request.user.project)


class CreateTaskProjectManager(CreateAPIView):
    serializer_class = TaskSerializer
    permission_classes = (IsProjectManagerUser,)

    def perform_create(self, serializer):
        instance = serializer.save(project=self.request.user.project)


class CreateUser(CreateAPIView):
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny]


class UserCreateList(ListCreateAPIView):
    serializer_class = UserSerializer
    queryset = CustomUser.objects.all()


class ProjectCreateList(ListCreateAPIView):
    serializer_class = ProjectSerializer
    queryset = Project.objects.all()
    permission_classes = (IsProjectManagerUser,)


class ProjectList(ListAPIView):
    serializer_class = ProjectSerializer
    queryset = Project.objects.all()
    permission_classes = (IsProjectManagerUser,)


class AssignUpdate(UpdateAPIView):
    serializer_class = AssigneeSerializer
    permission_classes = (IsProjectManagerUser,)


