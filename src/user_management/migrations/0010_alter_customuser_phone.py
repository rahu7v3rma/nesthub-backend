# Generated by Django 5.1 on 2025-06-16 14:05

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('user_management', '0009_customuser_profile_pic'),
    ]

    operations = [
        migrations.AlterField(
            model_name='customuser',
            name='phone',
            field=models.CharField(blank=True, max_length=15, null=True),
        ),
    ]
