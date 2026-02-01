from django.db import models

# Create your models here.

class Device(models.Model):
    ip = models.CharField(max_length=30)
    mac = models.CharField(max_length=30, unique=True)
    public_key = models.CharField(max_length=130, blank=True, null=True)
    manufacturer = models.TextField(blank=False, null=True)
    csr = models.TextField(blank=True, null=True)
    certificate = models.TextField(blank=True, null=True)
    last_active = models.DateTimeField(blank=True, null=True)