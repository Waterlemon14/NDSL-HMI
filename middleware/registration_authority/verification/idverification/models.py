from django.db import models

# Create your models here.

class Device(models.Model):
    ip = models.CharField(max_length=30)
    mac = models.CharField(max_length=30, unique=True)
    public_key = models.CharField(max_length=130)
    certificate = models.TextField(blank=True, null=True)