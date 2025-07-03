from django.contrib import admin

from .models import TrustMark, TrustMarkType

admin.site.register(TrustMarkType)
admin.site.register(TrustMark)
