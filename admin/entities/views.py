from django.core.paginator import Paginator
from django.db import IntegrityError
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django_redis import get_redis_connection

from .forms import EntityForm
from .lib import SubordinateRequest, add_subordinate
from .models import Subordinate

# Create your views here.


def index(request: HttpRequest) -> HttpResponse:
    return render(request, "entities/index.html")


def list_subordinates(request: HttpRequest) -> HttpResponse:
    subordinate_list = Subordinate.objects.all()
    paginator = Paginator(subordinate_list, 3)

    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)
    return render(request, "entities/list.html", {"page_obj": page_obj})


def add_subordinate_entity(request: HttpRequest) -> HttpResponse:
    msg = ""

    if request.method == "POST":
        form = EntityForm(request.POST)
        # check whether it's valid:
        if form.is_valid():
            subr = SubordinateRequest(entity=form.data["entity"])
            try:
                e = Subordinate(entityid=subr.entity)
                # save to database
                e.save()
                con = get_redis_connection("default")
                # Next create the actual trustmark
                add_subordinate(subr.entity, con)
                msg = f"Added {subr.entity} as subordinated"
            except IntegrityError:
                msg = f"{subr.entity} was already added as subordinate."
            except Exception as e:
                msg = f"Failed to add {subr.entity} due to {e}"
        else:
            print("Falied to validate the form.")
            msg = "Failed to validate the form."
    else:
        form = EntityForm(request.POST)

    return render(
        request,
        "entities/add.html",
        {"form": form, "msg": msg},
    )


# Create your views here.
