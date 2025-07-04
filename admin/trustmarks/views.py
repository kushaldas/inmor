from django.db import IntegrityError
from django.http import HttpResponse
from django.shortcuts import render
from django_redis import get_redis_connection

from .forms import TrustMarkForm
from .lib import add_trustmark
from .models import TrustMark, TrustMarkType

# Create your views here.


def index(request):
    return render(request, "trustmarks/index.html")


def addtrustmark(request):
    msg = ""
    tmts = TrustMarkType.objects.all()

    if request.method == "POST":
        form = TrustMarkForm(request.POST)
        # check whether it's valid:
        if form.is_valid():
            entity = form.data["entity"]
            tmt = form.data["tmt_select"]
            try:
                trust_mark_type = TrustMarkType.objects.get(id=tmt)
                t = TrustMark(tmt=trust_mark_type, domain=entity, active=True)
                # save to database
                t.save()
                con = get_redis_connection("default")
                # Next create the actual trustmark
                trust_mark = add_trustmark(entity, trust_mark_type.tmtype, con)
                msg = f"Added {entity}"
            except IntegrityError:
                msg = f"{entity} was already added for the selected Trust mark."
        else:
            print("invalid form")
    else:
        print("bad form")
        form = TrustMarkForm(request.POST)

    return render(
        request,
        "trustmarks/add.html",
        {"form": form, "trustmarktypes": tmts, "msg": msg},
    )
