from django.urls import path

from . import views

app_name = "trustmarks"

urlpatterns = [
    path("", views.index, name="index"),
    path("add/", views.addtrustmark, name="addtrustmark"),
    path("list/", views.listtrustmarks, name="listtrustmarks"),
    path("types/", views.type_index, name="type_index"),
    path("types/add/", views.add_trustmark_type, name="add_type"),
    path("types/list/", views.list_trustmark_types, name="list_types"),
]
