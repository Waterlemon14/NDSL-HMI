from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_exempt
import json
import requests

from idverification.mosip import otp_auth
from idverification.models import Device

# Create your views here.
@ensure_csrf_cookie
def index(request):
    return render(request, 'index.html')

def verify_qr(request):
    data = json.loads(request.body)
    uin = data.get('UIN')

    response_body = otp_auth.verify_qr(uin)
    errors = response_body.get('errors')

    if (errors == None):
        transaction_id = response_body["transactionID"]
        request.session["uin"] = uin
        request.session["transaction_id"] = transaction_id

        return JsonResponse({
            "status": "ok",
            "redirect": "/enter-otp",
        })
    
    return JsonResponse({ "status": "error" }, status=400)

def enter_otp(request):
    if "uin" not in request.session or "transaction_id" not in request.session:
        return redirect("/")

    if request.method == "POST":
        uin = request.session.get("uin")
        transaction_id = request.session.get("transaction_id")
        otp = request.POST.get("otp")

        response_body = otp_auth.verify_otp(uin, otp, transaction_id)
        errors = response_body.get('errors')

        print(response_body)

        if (errors == None):
            request.session["is_verified"] = True
            return redirect("select_device")
        
        return render(request, "enter-otp.html", {"error": "Invalid OTP"})

    return render(request, 'enter-otp.html')

def select_device(request):
    if not request.session.get("is_verified"):
        return redirect("/")
    
    devices = Device.objects.all()

    if request.method == "POST":
        action = request.POST.get("action")
        cert_file = "/home/chris/cs198/test_site/id_server.crt"
        key_file = "/home/chris/cs198/test_site/id_server_private.key"
        ca_file = "/home/chris/cs198/test_site/ca.crt"

        if action == "Send Request":
            device = Device.objects.get(id=int(request.POST.get("device-select")))
            print(device.id)

            ca_url = "https://localhost:15000/sign"
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

            if ca_response.status_code == 200:
                device.certificate = ca_response.text
                device.save()

                message = "Certificate available at /download-cert/" + str(device.mac)

                return render(request, "select-device.html", {"success": message, 'devices': Device.objects.all()})
            else:
                return render(request, "select-device.html", {"error": "Failed to get certificate", 'devices': Device.objects.all()})
            
            # csr = request.FILES.get("csr")
            # if not csr:
            #     return render(request, "enter-csr.html", {"error": "No file uploaded"})
            
            # csr_data = csr.read()
            # ca_url = "https://localhost:15000/sign"
            # headers = {"Content-Type": "application/pem-csr"}
            
            # ca_response = requests.post(
            #     ca_url,
            #     data=csr_data,
            #     headers=headers,
            #     # cert=("/home/chris/cs198/test_site/id_server.crt", "/home/chris/cs198/test_site/id_server_private.key"),
            #     # verify="/home/chris/cs198/test_site/ca.crt"
            #     verify=False
            # )
            
            # if ca_response.status_code == 200:
            #     cert_data = ca_response.content
            #     cert_filename = csr.name.replace(".csr", ".crt")

            #     # Return certificate to browser as a download
            #     response = HttpResponse(cert_data, content_type="application/x509-cert")
            #     response["Content-Disposition"] = f'attachment; filename="{cert_filename}"'
            #     return response
            # else:
            #     return render(request, "select-device.html", {"error": "Failed to get certificate", 'devices': Device.objects.all()})
        elif action == "Clear All Devices":
            Device.objects.all().delete()
            return render(request, 'select-device.html', {'devices': Device.objects.all()})
        elif action == "Ping Comms Server":
            commsurl = "https://192.168.0.212:8001/"

            response = requests.post(
                commsurl,
                json={"ping": "test"},
                cert=(cert_file, key_file),
                verify=ca_file
            )
            print(f"Status: {response.status_code}")
            print(f"Response: {response.text}")


    return render(request, 'select-device.html', {'devices': Device.objects.all()})

@csrf_exempt
def receive_device_data(request):
    response = HttpResponse()
    if request.method == "POST":
        data = json.loads(request.body)
        ip = data.get('IP')
        mac = data.get('MAC')
        pk = data.get('PublicKey')
        print(ip,mac)

        device, created = Device.objects.update_or_create(
            mac=mac,
            defaults={'ip':ip, 'public_key': pk},
        )

        print(device.id)
        
        response.status_code = 202
        return response

    response.status_code = 400
    return response

def download_cert(request, mac_address):
    device = Device.objects.get(mac=mac_address)
    if device.certificate:
        return HttpResponse(device.certificate, content_type="application/x-pem-file")
    return HttpResponse("Cert not ready", status=404)