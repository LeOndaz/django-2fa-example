# Generated by Django 4.0.4 on 2022-04-27 02:23

import account.models
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0002_user_groups_user_is_superuser_user_user_permissions'),
    ]

    operations = [
        migrations.AlterModelManagers(
            name='user',
            managers=[
                ('objects', account.models.UserManager()),
            ],
        ),
    ]
