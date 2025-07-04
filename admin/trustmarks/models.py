from django.db import models
from django.db.models.functions import Now


# Create your models here.
class TrustMarkType(models.Model):
    id: int
    tmtype = models.CharField()

    def __str__(self):
        return self.tmtype

    class Meta:
        indexes = [
            models.Index(fields=["tmtype"]),
        ]


class TrustMark(models.Model):
    id: int
    tmt = models.ForeignKey(TrustMarkType, on_delete=models.CASCADE)
    added = models.DateTimeField(db_default=Now())
    domain = models.CharField()
    active = models.BooleanField(default=False)

    def __str__(self):
        return self.domain

    class Meta:
        unique_together = ("tmt", "domain")
        indexes = [
            models.Index(fields=["domain"]),
            models.Index(fields=["active"]),
        ]
