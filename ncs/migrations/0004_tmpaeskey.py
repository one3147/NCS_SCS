# Generated by Django 5.0.3 on 2024-05-29 00:20

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("ncs", "0003_chatlog"),
    ]

    operations = [
        migrations.CreateModel(
            name="TmpAESKey",
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
                ("chatroom", models.CharField(max_length=255)),
                ("user", models.CharField(max_length=255)),
                ("aes_key", models.CharField(max_length=255)),
            ],
        ),
    ]
