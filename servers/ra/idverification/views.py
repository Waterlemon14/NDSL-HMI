from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_exempt
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from datetime import timedelta
import json
import requests
import ipaddress
import random

from idverification.mosip import otp_auth
from idverification.models import Device
from idverification.helper import get_select_list

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
    
    likely, others = get_select_list(request)

    if request.method == "POST":
        action = request.POST.get("action")
        if action == "Request Certificate":
            request.session["score"] = 0
            request.session["attempt"] = 1
            return redirect("/ownership-challenge/" + request.POST.get("device-select"))
        elif action == "Clear All Devices":
            Device.objects.all().delete()
            return render(request, 'select-device.html', {'likely': likely, 'others': others})
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

    return render(request, 'select-device.html', {'likely': likely, 'others': others})

@csrf_exempt
def receive_device_data(request):
    response = HttpResponse()
    if request.method == "POST":
        data = json.loads(request.body)
        ip = data.get('IP')
        mac = data.get('MAC')
        pk = data.get('PublicKey')
        csr = data.get('CSR')
        print(ip,mac)

        mac_response = requests.get("https://api.macvendors.com/"+mac)
        if mac_response.status_code != 200:
            print("Manufacturer cannot be determined")
            return HttpResponse("Manufacturer cannot be determined", status=404)
        manufacturer = mac_response.content.decode()

        now = timezone.now()

        device, created = Device.objects.update_or_create(
            mac=mac,
            defaults={
                'ip':ip,
                'manufacturer':manufacturer,
                'public_key': pk,
                'csr':csr,
                'last_active':now,
            },
        )

        print(device.id)
        
        response.status_code = 202
        return response

    response.status_code = 400
    return response

def download_cert(request, mac_address):
    device = Device.objects.get(mac=mac_address)
    print(timezone.localtime(device.last_active))
    now = timezone.now()
    device.last_active = now
    device.save()
    print(timezone.localtime(device.last_active))

    if device.certificate:
        return HttpResponse(device.certificate, content_type="application/x-pem-file")
    return HttpResponse("Cert not ready", status=404)

def ownership_challenge(request, device_id):
    device = Device.objects.get(id=device_id)
    print(device.ip)
    
    score = request.session["score"]
    attempt = request.session["attempt"]
    
    if score == 3:
        likely, others = get_select_list(request)
        cert_file = "/home/chris/cs198/NDSL-HMI/servers/ra/id_server.crt"
        key_file = "/home/chris/cs198/NDSL-HMI/servers/ra/id_server.key"
        ca_file = "/home/chris/cs198/NDSL-HMI/servers/ra/root-ca.crt"

        if device.public_key:
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

                return render(request, "select-device.html", {"success": message, 'likely': likely, 'others': others})
            else:
                print(ca_response.text)
                return render(request, "select-device.html", {"error": "Failed to get certificate", 'likely': likely, 'others': others})
        elif device.csr:
            csr_data = device.csr
            ca_url = "https://localhost:15000/sign"
            headers = {"Content-Type": "application/pem-csr"}
            
            ca_response = requests.post(
                ca_url,
                data=csr_data,
                headers=headers,
                cert=(cert_file, key_file),
                verify=ca_file
            )
            
            if ca_response.status_code == 200:
                device.certificate = ca_response.text
                device.save()

                message = "Certificate available at /download-cert/" + str(device.mac)

                return render(request, "select-device.html", {"success": message, 'likely': likely, 'others': others})
            else:
                print(ca_response.text)
                return render(request, "select-device.html", {"error": "Failed to get certificate", 'likely': likely, 'others': others})
    elif attempt == 5:
        return render(request, "select-device.html", {"error": "Failed to verify ownership of device", 'likely': likely, 'others': others})

    return render(request, 'ownership-challenge.html', {'device': device})

def start_challenge(request):
    if request.method == 'POST':
        request.session["start_time"] = timezone.now().isoformat()
        timer = random.randint(5,20)
        request.session["end_time"] = (timezone.now() + timedelta(seconds=timer)).isoformat()
        print("Start: ", timezone.localtime(parse_datetime(request.session["start_time"])))
        print("End: ", timezone.localtime(parse_datetime(request.session["end_time"])))
        print("Timer: ", timer)
        return JsonResponse({'status': 'ok', 'timer': timer})

def end_challenge(request, device_id):
    if request.method == 'POST':
        start_time = parse_datetime(request.session["start_time"])
        end_time = parse_datetime(request.session["end_time"])
        device = Device.objects.get(id=device_id)
        print("Start: ", timezone.localtime(parse_datetime(request.session["start_time"])))
        print("End: ", timezone.localtime(parse_datetime(request.session["end_time"])))
        print("Current: ", timezone.localtime(timezone.now()))
        print("Device: ", timezone.localtime(device.last_active))

        request.session["start_time"] = timezone.now().isoformat()
        request.session["end_time"] = (parse_datetime(request.session["start_time"]) + timedelta(seconds=10)).isoformat()
        if device.last_active < start_time:
            return JsonResponse({'status': 'before'})
        elif device.last_active >= start_time and device.last_active <= end_time:
            return JsonResponse({'status': 'between'})
        elif device.last_active > end_time:
            return JsonResponse({'status': 'after'})
        
        return JsonResponse({'status': 'error', 'message': 'unknown result'})