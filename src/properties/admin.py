# from django.contrib.admin import ModelAdmin, register
# from properties.models import Property


# @register(Property)
# class PropertyAdmin(ModelAdmin):
#     pass


from django.apps import apps
from django.contrib import admin


# Get all models from the 'properties' app
app = apps.get_app_config('properties')

for model in app.get_models():
    try:
        admin.site.register(model)
    except admin.sites.AlreadyRegistered:
        pass
