# Generated by Django 4.0.4 on 2022-04-28 18:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('account', '0004_alter_user_email'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='totp_hash',
        ),
        migrations.AddField(
            model_name='user',
            name='_totp_hash',
            field=models.CharField(db_column='totp_hash', default='1ccff6bd-3fe7-40db-a843-5d1b7543b13cnjvjkmnfhwzyfuxsmkzwcnheslafkenmfbvglznknnknkmrkfzmuctvleiwzvzebmhdkhdhsqovgdqfdngwgcwctsnaolulexruw', max_length=256),
        ),
    ]