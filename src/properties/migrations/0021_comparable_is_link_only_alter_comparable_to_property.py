# Generated by Django 5.1 on 2025-06-11 12:33

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ('properties', '0020_property_is_property_viewed_by_client'),
    ]

    operations = [
        migrations.AddField(
            model_name='comparable',
            name='is_link_only',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='comparable',
            name='to_property',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name='to_property_comparables',
                to='properties.realtorproperty',
            ),
        ),
    ]
