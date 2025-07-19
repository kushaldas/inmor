from django.core.paginator import Paginator
from django.db import IntegrityError
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django_redis import get_redis_connection

from .forms import EntityForm
from .lib import add_subordinate
from .models import Subordinate

# Create your views here.


def index(request: HttpRequest):
    return render(request, "entities/index.html")


def list_subordinates(request: HttpRequest):
    subordinate_list= Subordinate.objects.all()
    paginator = Paginator(subordinate_list, 3)

    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)
    return render(request, "entities/list.html", {"page_obj": page_obj})

def add_subordinate_entity(request: HttpRequest):
    msg = ""

    if request.method == "POST":
        form = EntityForm(request.POST)
        # check whether it's valid:
        if form.is_valid():
            entity = form.data["entity"]
            try:
                e = Subordinate(entityid=entity)
                # save to database
                e.save()
                con = get_redis_connection("default")
                # Next create the actual trustmark
                add_subordinate(entity, con)
                msg = f"Added {entity} as subordinated"
            except IntegrityError:
                msg = f"{entity} was already added as subordinate."
        else:
            print("invalid form")
    else:
        print("bad form")
        form = EntityForm(request.POST)

    return render(
        request,
        "entities/add.html",
        {"form": form, "msg": msg},
    )

# Create your views here.
