import ipaddress

from django.db.models import Q
from idverification.models import Device, State

def get_select_list(request):
    devices = Device.objects.filter((Q(certificate__isnull=True) & Q(owner__isnull=True)) | (Q(state=State.REVOKED) & Q(owner=request.user)))
    client_ip = int(ipaddress.ip_address(request.META.get('REMOTE_ADDR')))
    device_match = []
    for device in devices:
        device_ip = int(ipaddress.ip_address(device.ip))
        matched_prefix = 32 - (client_ip ^ device_ip).bit_length()
        device_match.append((device, matched_prefix))
    
    device_match.sort(key=lambda x: x[1], reverse=True)
    sorted_devices = [dev for dev, matched in device_match]
    
    likely = sorted_devices [:5]
    others = sorted_devices [5:]

    return (likely, others)
