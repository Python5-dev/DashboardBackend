# Generated by Django 5.1.6 on 2025-04-17 17:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0014_logactivities_username_or_email'),
    ]

    operations = [
        migrations.AlterField(
            model_name='logactivities',
            name='time',
            field=models.JSONField(default=list),
        ),
    ]
