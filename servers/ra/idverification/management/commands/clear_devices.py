from django.core.management.base import BaseCommand

from idverification.models import Device

class Command(BaseCommand):
    help = 'Clear all devices from the database'

    def handle(self, *args, **kwargs):
        self.stdout.write("Clearing devices...")
        Device.objects.all().delete()

        self.stdout.write(
            self.style.SUCCESS(f'Successfully deleted all devices!')
        )