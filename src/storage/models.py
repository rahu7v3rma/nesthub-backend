from django.db import models

from lib.models import BaseModel


class GoogleOAuthAuthorizationRequest(BaseModel):
    state = models.TextField()
    used = models.BooleanField(default=False)


class GoogleOAuthToken(BaseModel):
    refresh_token = models.TextField()
    access_token = models.TextField()
    expires_at = models.FloatField()
