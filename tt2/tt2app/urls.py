from django.urls import path, include
from .views import TasksList
app_name = "tt2app"

urlpatterns = [
    path("<int:pj>", TasksList.as_view(), name="tasklist"),
]
