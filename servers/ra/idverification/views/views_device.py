import json
import requests
import math
from pathlib import Path
from cryptography import x509

from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

from idverification.models import Device

basePathToRepo = Path(__file__).parent.parent.parent.parent.parent

ca_url = "https://localhost:15000/sign"
ca_renew_url = "https://localhost:15000/renew"

cert_file = basePathToRepo / "servers" / "ra" / "id_server.crt"
key_file = basePathToRepo / "servers" / "ra" / "id_server.key"
ca_file = basePathToRepo / "servers" / "ra" / "root-ca.crt"

CHALLENGE_COUNT_THRESHOLD = 3

# Create your views here.
@csrf_exempt
def receive_device_data(request):
    response = HttpResponse()

    if request.method == "POST":
        data = json.loads(request.body)
        ip = data.get('IP')
        mac = data.get('MAC')
        pk = data.get('PublicKey')
        csr = data.get('CSR')
        challengeCount = 0
        owner = None
        print(ip,mac)
        
        device = Device.objects.filter(mac=mac).first()

        if device:
            challengeCount = device.challengeCount        
            manufacturer = device.manufacturer
            owner = device.owner
        
        else:
            mac_response = requests.get("https://api.macvendors.com/"+mac)
            if mac_response.status_code != 200:
                print("Manufacturer cannot be determined: ", mac_response.status_code)
                return HttpResponse("Manufacturer cannot be determined", status=404)
            manufacturer = mac_response.content.decode()
        
        device, _ = Device.objects.update_or_create(
            mac=mac,
            defaults={
                'ip':ip, 
                'manufacturer':manufacturer,
                'public_key': pk, 
                'csr':csr, 
                'challengeCount': challengeCount,
                'owner': owner
                },
        )

        print("Device",device.id,"Challenge Count: ", device.challengeCount, "updatedAt: ", device.updatedAt)

        if device.challengeCount == CHALLENGE_COUNT_THRESHOLD or device.certificate:
            response.status_code = 202
        else:
            response.status_code = 201

        return response
    
    response.status_code = 400
    return response

def download_cert(request, mac_address):
    device = Device.objects.get(mac=mac_address)
    if device.certificate:
        cert = x509.load_pem_x509_certificate(device.certificate.encode('utf-8'))
        expiration = math.floor(cert.not_valid_after_utc.timestamp())
        response = HttpResponse(device.certificate, content_type="application/x-pem-file")
        response['X-Cert-Expires-At'] = str(expiration)
        return response

    elif device.challengeCount == CHALLENGE_COUNT_THRESHOLD:
        if device.public_key:
            headers = {"Content-Type": "application/json"}
            payload = {
                "PublicKey": device.public_key,
                "IPAddress": device.ip,
                "Subject": {
                    "Country": "PH",
                    "State": "Metro Manila",
                    "Locality": "Quezon City",
                    "Organization": "MyIoTProject",
                    "CommonName": device.ip,
                },
            }

            ca_response = requests.post(
                ca_url,
                json=payload,
                headers=headers,
                cert=(cert_file, key_file),
                verify=ca_file
                # verify=False
            )

        elif device.csr:
            headers = {"Content-Type": "application/pem-csr"}
            payload = device.csr

            ca_response = requests.post(
                ca_url,
                data=payload,
                headers=headers,
                cert=(cert_file, key_file),
                verify=ca_file
                # verify=False
            )

        if ca_response.status_code == 200:
            device.certificate = ca_response.text
            device.challengeCount = 0
            device.save()

        else:
            print(ca_response.text)

        return HttpResponse(device.certificate, content_type="application/x-pem-file")

    return HttpResponse("Cert not ready", status=404)

@csrf_exempt
def renew_cert(request, mac_address):
    if request.method != "POST":
        return HttpResponse("Method not allowed", status=405)

    try:
        device = Device.objects.get(mac=mac_address)
    except Device.DoesNotExist:
        return HttpResponse("Device not found", status=404)

    cert_pem = request.body

    ca_response = requests.post(
        ca_renew_url,
        data=cert_pem,
        headers={"Content-Type": "application/x-pem-file"},
        cert=(cert_file, key_file),
        verify=ca_file,
    )

    if ca_response.status_code == 200:
        device.certificate = ca_response.text
        device.save()
        cert = x509.load_pem_x509_certificate(device.certificate.encode('utf-8'))
        expiration = math.floor(cert.not_valid_after_utc.timestamp())
        response = HttpResponse(device.certificate, content_type="application/x-pem-file")
        response['X-Cert-Expires-At'] = str(expiration)
        return response

    print("CA renew error:", ca_response.status_code, ca_response.text)
    return HttpResponse(ca_response.text, status=ca_response.status_code)