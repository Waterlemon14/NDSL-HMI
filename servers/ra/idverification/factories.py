import factory
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from idverification.models import Device

def generate_ec_key():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    return public_key.hex()

class DeviceFactory(factory.django.DjangoModelFactory):
    class Meta:
        model = Device

    ip = factory.Faker('ipv4_private')
    mac = factory.Faker('mac_address')
    public_key = factory.LazyFunction(generate_ec_key)

