from datetime import timedelta

import random

from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import ensure_csrf_cookie, csrf_exempt
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.contrib import messages
from django.contrib.auth import login, logout
from django.db.models import Case, When
from datetime import timedelta

import json
import requests
from pathlib import Path


from idverification.mosip import otp_auth
from idverification.models import Device, User, State
from idverification.helper import get_select_list

registeringMACs = []

CHALLENGE_COUNT_THRESHOLD = 3

basePathToRepo = Path(__file__).parent.parent.parent.parent

ca_url = "https://localhost:15000/sign"
ca_renew_url = "https://localhost:15000/renew"
ca_revoke_url = "https://localhost:15000/revoke"

cert_file = basePathToRepo / "servers" / "ra" / "id_server.crt"
key_file = basePathToRepo / "servers" / "ra" / "id_server.key"
ca_file = basePathToRepo / "servers" / "ra" / "root-ca.crt"

registeringMACs = []

CHALLENGE_COUNT_THRESHOLD = 3

# Create your views here.
@ensure_csrf_cookie
def index(request):
    return render(request, 'index.html')

def verify_qr(request):
    data = json.loads(request.body)
    uin = data.get('UIN')
    lastName = data.get('lName')
    firstName = data.get('fName')

    response_body = otp_auth.verify_qr(uin)
    errors = response_body.get('errors')

    if (errors == None):
        transaction_id = response_body["transactionID"]
        request.session["uin"] = uin
        request.session["transaction_id"] = transaction_id
        request.session["lastName"] = lastName
        request.session["firstName"] = firstName

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

        if (errors == None and request.session.get("firstName") and request.session.get("lastName")):
            user, created = User.objects.get_or_create(
                uin=uin,
                defaults={
                    'firstName': request.session["firstName"],
                    'lastName': request.session["lastName"],
                }
            )

            if created:
                user.set_unusable_password()
                user.save()
            
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            
            return redirect("select_device")
        
        return render(request, "enter-otp.html", {"error": "Invalid OTP"})

    return render(request, 'enter-otp.html')

def select_device(request):
    if not request.user.is_authenticated:
        return redirect("/")
    
    likely, others = get_select_list(request)

    if request.method == "POST":
        action = request.POST.get("action")
        device_id = request.POST.get("device_id")
        if action == "Request Certificate":
            if Device.objects.get(id=device_id).certificate:
                return render(request, 'select-device.html', {'likely': likely, 'others': others, 'error': "Device certificate already available."})
            else:
                return redirect("/ownership-challenge/" + device_id)
    
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

        if device.challengeCount == CHALLENGE_COUNT_THRESHOLD:
            response.status_code = 202
        else:
            response.status_code = 201

        return response
    
    response.status_code = 400
    return response

def download_cert(request, mac_address):
    device = Device.objects.get(mac=mac_address)
    if device.certificate:
        return HttpResponse(device.certificate, content_type="application/x-pem-file")

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
        return HttpResponse(device.certificate, content_type="application/x-pem-file")

    print("CA renew error:", ca_response.status_code, ca_response.text)
    return HttpResponse(ca_response.text, status=ca_response.status_code)

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
                    print(f"Revoked certificate for reported device {mac}")
                else:
                    print(f"CA revoke failed for {mac}: {ca_response.status_code} {ca_response.text}")
        except Device.DoesNotExist:
            pass  # MAC not registered in RA

    return HttpResponse("Device Suspended", status=200)


def ownership_challenge(request, device_id):
    if not request.user.is_authenticated:
        return redirect("/")
        
    device = Device.objects.get(id=int(device_id))

    return render(request, "ownership-challenge.html", {"info": "Disconnect your device now", "device": device})

def start_challenge(request, device_id):
    device = Device.objects.get(id=int(device_id))
    if request.method == 'POST':
        # initialize challenge sequence
        interval = random.randint(11, 20)
        message = "Starting Human Challenges\nReset your device with MAC Address: " + \
            str(device.mac) + \
            ", and after " + str(interval) + " seconds of downtime, reconnect within 30 seconds.\n" + \
            "Count: " + str(device.challengeCount)

        device.interval = interval
        device.save()

        request.session["start_time"] = timezone.now().isoformat()
        request.session["end_time"] = (timezone.now() + timedelta(seconds=interval)).isoformat()

        return JsonResponse({"status": "ok", "interval": interval, "mac": device.mac, "count": device.challengeCount})

def check_status(request, device_id):
    device = Device.objects.get(id=int(device_id))
    if request.method == 'POST':
        data = json.loads(request.body)
        print("post received: ", data.get('action'))
        if data.get('action') == 'end':
            print("end")
            if device:
                start = parse_datetime(request.session["start_time"])
                end = parse_datetime(request.session["end_time"])
                last_active = device.updatedAt

                if last_active > end or last_active < start:
                    request.session["start_time"] = timezone.now().isoformat()
                    request.session["end_time"] = (timezone.now() + timedelta(seconds=30)).isoformat()
                    return JsonResponse({"status": "ok", 'interval': 30, "count": device.challengeCount})
                else:
                    device.challengeCount = 0
                    device.save()
                    return JsonResponse({"status": "fail", "count": device.challengeCount})

        elif data.get('action') == 'check':
            print("checking")
            if device:
                start = parse_datetime(request.session["start_time"])
                end = parse_datetime(request.session["end_time"])
                last_active = device.updatedAt

                if start <= last_active <= end:
                    device.challengeCount += 1
                    device.save()
                    
                    if device.challengeCount == CHALLENGE_COUNT_THRESHOLD:
                        messages.success(request, "Ownership challenge complete! Certificate now available for device with MAC address " + device.mac + ".")
                        device.owner = request.user
                        device.save()
                        return JsonResponse({"status": "complete", "count": device.challengeCount, "redirect": "/select-device",})
                    else:
                        return JsonResponse({"status": "ok", "count": device.challengeCount})
                
                else:
                    return JsonResponse({"status": "waiting", "count": device.challengeCount})
        
        elif data.get('action') == 'fail':
            print("updating")
            if device:
                device.challengeCount = 0
                device.save()
                return JsonResponse({"status": "updated", "count": device.challengeCount})

def view_device(request):
    if not request.user.is_authenticated:
        return redirect("/")

    devices = request.user.devices.all().annotate(
        state_priority=Case(
            When(state=State.SUSPENDED, then=0),
            When(state=State.RECONNECTING, then=1),
            When(state=State.CONNECTED, then=2),
            default=3,
        )
    ).order_by("state_priority", "-updatedAt")

    if request.method == "POST":
        device_id = request.POST.get("device_id")
        action = request.POST.get("action")
        try:
            device = Device.objects.get(id=int(device_id))
            if action == "Reconnect":
                device.state = State.RECONNECTING
                device.save()
                messages.success(request, f"Device {device.mac.upper()} set to {State.RECONNECTING}.")
                
            elif action == "Revoke":
                if not device.certificate:
                    messages.error(request, "Device has no certificate to revoke.")
                    return redirect("view_device")

                ca_response = requests.post(
                    ca_revoke_url,
                    json={"certificate": device.certificate, "reason": "user_revoked"},
                    cert=(cert_file, key_file),
                    verify=ca_file,
                )

                if ca_response.status_code == 200:
                    device.certificate = ""
                    device.state = State.REVOKED
                    device.save()
                    messages.success(request, f"Certificate for {device.mac} has been revoked.")
                else:
                    print("CA revoke error:", ca_response.status_code, ca_response.text)
                    messages.error(request, f"Failed to revoke certificate: {ca_response.text}")

            return redirect("view_device")
        except (ValueError, Device.DoesNotExist):
            messages.error(request, f"Could not find device.")
    
    return render(request, 'view-device.html', {'devices': devices, "state_choices": State.CHOICES})

def reconnect_device(request, mac_address):
    print(mac_address)
    try:
        device = Device.objects.get(mac=mac_address)
        device.state = State.CONNECTED
        device.save()
    except Device.DoesNotExist:
        pass  # MAC not registered in RA
    
    return HttpResponse("Device Reconnected", status=200)

def logout_view(request):
    logout(request)
    return redirect("index")