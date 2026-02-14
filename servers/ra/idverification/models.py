from django.db import models

# Create your models here.

class State:
    CONNECTED = 'connected'
    RECONNECTING = 'reconnecting'
    SUSPENDED = 'suspended'

    CHOICES = [
        (CONNECTED, 'Connected'),
        (RECONNECTING, 'Reconnecting'),
        (SUSPENDED, 'Suspended'),
    ]

class Device(models.Model):
    updatedAt = models.DateTimeField(auto_now=True)

    mac = models.CharField(max_length=30, unique=True)
    ip = models.CharField(max_length=30)

    public_key = models.CharField(max_length=130, blank=True, null=True)
    manufacturer = models.TextField(blank=False, null=True)
    csr = models.TextField(blank=True, null=True)
    
    challengeCount = models.SmallIntegerField(default=0)
    interval = models.SmallIntegerField(default=1000000)

    certificate = models.TextField(blank=True, null=True)

    state = models.CharField(
        max_length=20,
        choices=State.CHOICES,
        default=State.CONNECTED,
    )