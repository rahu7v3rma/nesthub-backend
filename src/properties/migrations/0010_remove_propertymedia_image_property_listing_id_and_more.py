# Generated by Django 5.1 on 2025-05-12 20:29

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ('properties', '0009_alter_clientproperty_realtor_property'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='propertymedia',
            name='image',
        ),
        migrations.AddField(
            model_name='property',
            name='listing_id',
            field=models.IntegerField(blank=True, default=None, null=True),
        ),
        migrations.AddField(
            model_name='propertymedia',
            name='photos_list',
            field=models.JSONField(blank=True, default=list, null=True),
        ),
        migrations.AlterField(
            model_name='propertymedia',
            name='property_id',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name='property_media',
                to='properties.property',
            ),
        ),
    ]
