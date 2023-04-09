from rest_framework import serializers
from tt2app.models import CustomUser, Project, Task
from django.contrib.auth.hashers import make_password
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('username', 'email', 'password', 'is_developer', 'is_projectmanager')

    def create(self, validated_data):
        user = CustomUser(
            username=validated_data['username'],
            email=validated_data['email'],
            password=make_password(validated_data['password']),
            is_developer=validated_data['is_developer'],
            is_projectmanager=validated_data['is_projectmanager'],
        )
        user.save()
        return user


class ProjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = Project
        fields = "__all__"


class TaskSerializer(serializers.ModelSerializer):
    project = serializers.StringRelatedField(many=False)

    class Meta:
        model = Task
        fields = "__all__"


class DeveloperTaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = ['name', 'description', 'completed']


class ProjectManagerTaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = ['name', 'description', 'completed', 'user']


class AssigneeSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ['username', 'project', 'is_developer']



