# Generated by Django 5.1 on 2025-05-22 13:39

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ('properties', '0017_alter_disclosure_property_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='realtorproperty',
            name='is_added_for_comparable',
            field=models.BooleanField(default=False),
        ),
    ]
