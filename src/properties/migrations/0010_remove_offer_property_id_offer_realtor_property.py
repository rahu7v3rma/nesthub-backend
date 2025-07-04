# Generated by Django 5.1 on 2025-05-12 17:28

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ('properties', '0009_alter_clientproperty_realtor_property'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='offer',
            name='property_id',
        ),
        migrations.AddField(
            model_name='offer',
            name='realtor_property',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name='offers',
                to='properties.realtorproperty',
            ),
        ),
    ]
