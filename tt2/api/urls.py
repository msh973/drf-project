from django.urls import path, include
from .views import TasksList, CreateTaskDeveloper, CreateTaskProjectManager, CreateUser, ProjectCreateList, UserCreateList, ProjectList, AssignUpdate, UserTasksList
app_name = "tt2app"


urlpatterns = [
    path("TL/<int:pjid>", TasksList.as_view(), name="tasklist"),
    path("DTC/", CreateTaskDeveloper.as_view(), name="createtaskdeveloper"),
    path("PJTC/", CreateTaskProjectManager.as_view(), name="createtaskprojectmanager"),
    path("UC/", CreateUser.as_view(), name="createuser"),
    path("PCL/", ProjectCreateList.as_view(), name="projectcreatelist"),
    path("UCL/", UserCreateList.as_view(), name="usercreatelist"),
    path("PL/", ProjectList.as_view(), name="projectlist"),
    path("AU/", AssignUpdate.as_view(), name="projectassign"),
    path("UTL/", UserTasksList.as_view(), name="usertasklist"),

]
