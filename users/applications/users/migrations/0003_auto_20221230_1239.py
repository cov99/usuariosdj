# Generated by Django 3.2.9 on 2022-12-30 15:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0002_auto_20221230_1206'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='is_staff',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='user',
            name='username',
            field=models.CharField(max_length=11, unique=True),
        ),
    ]
