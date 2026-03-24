import json
import requests
from pathlib import Path

from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib import messages

from idverification.models import Device, State, Notification

basePathToRepo = Path(__file__).parent.parent.parent

ca_revoke_url = "https://54.241.87.38:15000/revoke"

cert_file = basePathToRepo / "id_server.crt"
key_file = basePathToRepo / "id_server.key"
ca_file = basePathToRepo / "root-ca.crt"

# Create your views here.

@csrf_exempt
def report_device(request):
    if request.method != "POST":
        return HttpResponse("Method not allowed", status=400)
    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return HttpResponse("Invalid JSON", status=400)

    print(data)
    mac = data.get("mac")
    anomaly = data.get("anomaly")

    if anomaly == "disconnected":
        try:
            device = Device.objects.get(mac=mac)
            device.state = State.SUSPENDED
            device.save()
            if device.owner:
                Notification.objects.create(
                    user=device.owner,
                    level=Notification.ERROR,
                    message=f"Device {mac} was disconnected and marked as suspended."
                )
        except Device.DoesNotExist:
            pass  # MAC not registered in RA
    else: #elif anomaly == "stolen":
        try:
            device, _ = Device.objects.update_or_create(
                mac=mac,
                defaults={'state': State.REVOKED},
            )

            if device.certificate:
                ca_response = requests.post(
                    ca_revoke_url,
                    json={"certificate": device.certificate, "reason": "device_stolen"},
                    cert=(cert_file, key_file),
                    verify=ca_file,
                )
                if ca_response.status_code == 200:
                    device.certificate = ""
                    device.save()
                    print(f"Revoked certificate for reported stolen device {mac}")
                    if device.owner:
                        Notification.objects.create(
                            user=device.owner,
                            level=Notification.ERROR,
                            message=f"Device {mac} has been stolen and its certificate has been revoked"
                        )
                else:
                    print(f"CA revoke failed for {mac}: {ca_response.status_code} {ca_response.text}")
        except Device.DoesNotExist:
            pass  # MAC not registered in RA

    return HttpResponse("Device Suspended", status=200)

def reconnect_device(request, mac_address):
    print(mac_address)
    try:
        device = Device.objects.get(mac=mac_address)
        device.state = State.CONNECTED
        device.save()
    except Device.DoesNotExist:
        pass  # MAC not registered in RA
    
    return HttpResponse("Device Reconnected", status=200)