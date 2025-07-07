from django.db import models
from django.db.models.functions import Now


# Create your models here.
class Subordinate(models.Model):
    id: int
    added = models.DateTimeField(db_default=Now())
    entityid = models.CharField(unique=True)

    def __str__(self):
        return self.entityid

    class Meta:
        indexes = [
            models.Index(fields=["entityid"]),
        ]
