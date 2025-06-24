import uuid

from django.db import models

from lib.models import BaseModel
from user_management.models import CustomUser


class Property(models.Model):
    name = models.CharField(max_length=255, null=True, blank=True, default=None)
    address = models.TextField(null=True, blank=True, default=None)
    listing_id = models.IntegerField(null=True, blank=True, default=None)
    city = models.CharField(max_length=255, null=True, blank=True, default=None)
    county_or_parish = models.CharField(
        max_length=255, null=True, blank=True, default=None
    )
    state_or_province = models.CharField(
        max_length=255, null=True, blank=True, default=None
    )
    zip_code = models.CharField(max_length=20, null=True, blank=True, default=None)
    image = models.URLField(null=True, blank=True, default=None)
    price = models.PositiveIntegerField(blank=True, null=True, default=None)
    no_of_beds = models.PositiveIntegerField(blank=True, null=True, default=None)
    no_of_baths = models.PositiveIntegerField(blank=True, null=True, default=None)
    square_feet_size = models.PositiveIntegerField(blank=True, null=True, default=None)
    additional_information = models.TextField(blank=True, null=True, default=None)
    tag = models.CharField(max_length=255, null=True, blank=True, default=None)
    open_house_time = models.DateTimeField(null=True)
    deadline_datetime = models.DateTimeField(null=True, blank=True, default=None)
    is_deadline_checked = models.BooleanField(default=False)
    is_property_viewed_by_client = models.BooleanField(
        null=True, blank=True, default=False
    )
    note = models.TextField(blank=True, null=True, default=None)
    redfin_url = models.TextField(blank=True, null=True, default=None)
    zillow_url = models.TextField(blank=True, null=True, default=None)
    latitude = models.FloatField(blank=True, null=True, default=None)
    longitude = models.FloatField(blank=True, null=True, default=None)
    created_at = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, null=True, blank=True)

    def __str__(self):
        return self.name

    class Meta:
        verbose_name = 'Property'
        verbose_name_plural = 'Properties'


class PropertyDetail(models.Model):
    property = models.ForeignKey(
        Property, on_delete=models.CASCADE, related_name='property_details'
    )
    zillow_url = models.URLField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    open_house = models.CharField(max_length=255, blank=True, null=True, default=None)

    def __str__(self):
        return f'{self.property_id.name} details'


class PropertyMedia(models.Model):
    property_id = models.ForeignKey(
        Property, on_delete=models.CASCADE, related_name='property_media'
    )
    photos_list = models.JSONField(blank=True, null=True, default=list)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f'{self.property_id.name} media'


class RealtorProperty(models.Model):
    comparables = models.ManyToManyField('self', through='Comparable')
    is_added_for_comparable = models.BooleanField(default=False)
    property = models.ForeignKey(
        Property, on_delete=models.CASCADE, related_name='realtor_properties'
    )
    client = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name='client_realtor_properties'
    )
    realtor = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name='realtor_realtor_properties'
    )
    price = models.PositiveIntegerField(null=True, blank=True)
    property_rating = models.FloatField(null=True, blank=True)
    is_property_toured = models.BooleanField(default=False)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'RealtorProperty for {self.property.name} by {self.realtor.name}'


class ClientProperty(models.Model):
    is_added_for_comparable = models.BooleanField(default=False)
    realtor_property = models.ForeignKey(
        RealtorProperty, on_delete=models.CASCADE, related_name='realtor_properties'
    )
    client = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name='client_properties'
    )
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'ClientProperty linked to RealtorProperty {self.realtor_property_id}'


class Offer(BaseModel):
    realtor_property = models.ForeignKey(
        RealtorProperty, on_delete=models.CASCADE, related_name='offers'
    )
    amount = models.PositiveIntegerField()
    bidder_id = models.CharField(max_length=20)
    description = models.TextField(null=True, blank=True)
    contingencies_info = models.JSONField(null=True, blank=True)
    offer_date = models.DateField(null=True, blank=True)


class Disclosure(BaseModel):
    property_id = models.ForeignKey(
        RealtorProperty, on_delete=models.CASCADE, related_name='property_disclosures'
    )
    name = models.CharField(max_length=100, null=True, blank=True)
    description = models.TextField(null=True)
    url = models.TextField(null=True)


class DisclosureFile(models.Model):
    disclosure = models.ForeignKey(
        Disclosure, on_delete=models.CASCADE, related_name='files'
    )
    file = models.FileField(upload_to='disclosures/')

    @staticmethod
    def random_image_name(instance, filename):
        ext = filename.split('.')[-1]
        # Generate a unique filename using uuid
        new_filename = f'{uuid.uuid4().hex}.{ext}'
        return new_filename

    def save(self, *args, **kwargs):
        # If the file is being uploaded, change the filename
        if self.file:
            self.file.name = self.random_image_name(self, self.file.name)
        super().save(*args, **kwargs)


class Comparable(BaseModel):
    from_property = models.ForeignKey(
        RealtorProperty,
        on_delete=models.CASCADE,
        related_name='from_property_comparables',
    )
    to_property = models.ForeignKey(
        RealtorProperty,
        on_delete=models.CASCADE,
        related_name='to_property_comparables',
        null=True,
        blank=True,
    )
    url = models.CharField(max_length=255, null=True)
    additional_info = models.JSONField(null=True, blank=True)
    is_link_only = models.BooleanField(default=False)

    class Meta:
        unique_together = ('from_property', 'to_property')
        verbose_name = 'Property Comparable'
        verbose_name_plural = 'Property Comparables'


class Message(BaseModel):
    user = models.ForeignKey(
        CustomUser, on_delete=models.CASCADE, related_name='user_property_messages'
    )
    property = models.ForeignKey(
        Property, on_delete=models.CASCADE, related_name='property_messages'
    )
    message = models.TextField()

    def __str__(self):
        return (
            f'Message from {self.user} on property {self.property} '
            f'at {self.created_date}'
        )
