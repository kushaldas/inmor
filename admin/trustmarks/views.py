from django.core.paginator import Paginator
from django.db import IntegrityError
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django_redis import get_redis_connection

from redis import Redis

from .forms import TrustMarkForm
from .lib import TrustMarkRequest, add_trustmark
from .models import TrustMark, TrustMarkType

# Create your views here.


def index(request: HttpRequest):
    return render(request, "trustmarks/index.html")


def listtrustmarks(request: HttpRequest):
    trust_mark_list = TrustMark.objects.all()
    paginator = Paginator(trust_mark_list, 3)

    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)
    return render(request, "trustmarks/list.html", {"page_obj": page_obj})


def addtrustmark(request: HttpRequest) -> HttpResponse:
    msg = ""
    tmts = TrustMarkType.objects.all()

    if request.method == "POST":
        form = TrustMarkForm(request.POST)
        # check whether it's valid:
        if form.is_valid():
            tmr = TrustMarkRequest(entity=form.data["entity"], tmt_select=form.data["tmt_select"])
            try:
                trust_mark_type = TrustMarkType.objects.get(id=tmr.tmt_select)
                t = TrustMark(tmt=trust_mark_type, domain=tmr.entity, active=True)
                # save to database
                t.save()
                con: Redis = get_redis_connection("default")
                # Next create the actual trustmark
                _trust_mark = add_trustmark(tmr.entity, trust_mark_type.tmtype, con)
                msg = f"Added {tmr.entity}"
            except IntegrityError:
                msg = f"{tmr.entity} was already added for the selected Trust mark."
        else:
            print("invalid form")
            msg = "Form validation failed."
    else:
        print("Bad request.")
        form = TrustMarkForm(request.POST)

    return render(
        request,
        "trustmarks/add.html",
        {"form": form, "trustmarktypes": tmts, "msg": msg},
    )
