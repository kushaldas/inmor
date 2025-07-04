from django.urls import path

from . import views

app_name = "trustmarks"

urlpatterns = [
    path("", views.index, name="index"),
    path("add/", views.addtrustmark, name="addtrustmark"),
    path("list/", views.listtrustmarks, name="listtrustmarks"),
]
