from django.core.management.base import BaseCommand

from idverification.factories import DeviceFactory
from idverification.models import Device, User

class Command(BaseCommand):
    help = 'Uses DeviceFactory to fill the database with dummy IoT devices'

    def add_arguments(self, parser):
        # Named (optional) arguments
        parser.add_argument(
            "--clear",
            action="store_true",
            help="Clear old devices before seeding"
        )
        parser.add_argument(
            '--total',
            type=int,
            default=10,
            help='Number of devices to create (default is 10)',
        )
        parser.add_argument(
            "--user",
            type=str,
            help="Attach devices to the given user first name"
        )

    def handle(self, *args, **options):
        if options["clear"]:
            self.stdout.write("Clearing old devices...")
            Device.objects.all().delete()
        
        self.stdout.write(f"Creating {options["total"]} new devices...")
        new_devices = DeviceFactory.create_batch(options["total"])

        if options["user"]:
            try:
                user = User.objects.get(firstName=options["user"])
                for device in new_devices:
                    device.owner = user
                    device.save()
                self.stdout.write(self.style.SUCCESS(f"Assigned {options["total"]} devices to {options["user"]}"))
            except User.DoesNotExist:
                self.stdout.write(self.style.WARNING(f"User {options["user"]} not found. Devices left unassigned."))

        self.stdout.write(
            self.style.SUCCESS(f'Successfully seeded {options["total"]} devices!')
        )