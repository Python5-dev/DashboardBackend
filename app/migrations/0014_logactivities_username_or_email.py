# Generated by Django 5.1.6 on 2025-04-17 12:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0013_remove_logactivities_user'),
    ]

    operations = [
        migrations.AddField(
            model_name='logactivities',
            name='username_or_email',
            field=models.CharField(default='No User', max_length=100),
        ),
    ]
