# Generated by Django 5.2.3 on 2025-07-03 09:03

import django.db.models.deletion
import django.db.models.functions.datetime
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="TrustMarkType",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("tmtype", models.CharField()),
            ],
            options={
                "indexes": [models.Index(fields=["tmtype"], name="trustmarks__tmtype_c08ed8_idx")],
            },
        ),
        migrations.CreateModel(
            name="TrustMark",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "added",
                    models.DateTimeField(db_default=django.db.models.functions.datetime.Now()),
                ),
                ("domain", models.CharField()),
                ("active", models.BooleanField(default=False)),
                (
                    "tmt",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="trustmarks.trustmarktype",
                    ),
                ),
            ],
            options={
                "indexes": [
                    models.Index(fields=["domain"], name="trustmarks__domain_101ea9_idx"),
                    models.Index(fields=["active"], name="trustmarks__active_292a4b_idx"),
                ],
            },
        ),
    ]
