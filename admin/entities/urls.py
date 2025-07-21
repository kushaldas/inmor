from django.urls import path

from . import views

app_name = "entities"

urlpatterns = [
    path("", views.index, name="index"),
    path("add/", views.add_subordinate_entity, name="add_subordinate_entity"),
    path("list/", views.list_subordinates, name="list_subordinates"),
]
