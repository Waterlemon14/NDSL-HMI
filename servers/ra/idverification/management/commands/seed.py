from django.core.management.base import BaseCommand

from idverification.factories import DeviceFactory
from idverification.models import Device

class Command(BaseCommand):
    help = 'Uses DeviceFactory to fill the database with dummy IoT devices'

    def handle(self, *args, **kwargs):
        self.stdout.write("Clearing old devices...")
        Device.objects.all().delete()

        self.stdout.write("Creating 10 new devices...")
        DeviceFactory.create_batch(10)

        self.stdout.write(
            self.style.SUCCESS(f'Successfully seeded 10 devices!')
        )