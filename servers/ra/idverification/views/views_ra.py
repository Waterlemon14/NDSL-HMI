from datetime import timedelta
from pathlib import Path

import random
import json
import requests

from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.views.decorators.csrf import ensure_csrf_cookie
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.contrib import messages
from django.contrib.auth import login, logout
from django.db.models import Case, When

from idverification.mosip import otp_auth
from idverification.models import Device, User, State
from idverification.helper import get_select_list

basePathToRepo = Path(__file__).parent.parent.parent.parent.parent

ca_revoke_url = "https://localhost:15000/revoke"

cert_file = basePathToRepo / "servers" / "ra" / "id_server.crt"
key_file = basePathToRepo / "servers" / "ra" / "id_server.key"
ca_file = basePathToRepo / "servers" / "ra" / "root-ca.crt"

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

def ownership_challenge(request, device_id):
    if not request.user.is_authenticated:
        return redirect("/")
        
    device = Device.objects.get(id=int(device_id))

    if device.certificate:
        previous_url = request.META.get('HTTP_REFERER')
        
        if previous_url:
            return redirect(previous_url)
        else:
            return redirect("/")

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
                        if device.state == State.REVOKED:
                            redirect = "/view-device"
                        else:
                            redirect = "/select-device"
                        device.owner = request.user
                        device.state = State.RECONNECTING
                        device.save()
                        messages.success(request, "Ownership challenge complete! Certificate now available for device with MAC address " + device.mac + ".")
                        return JsonResponse({"status": "complete", "count": device.challengeCount, "redirect": redirect,})
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
                    device.challengeCount = 0
                    device.state = State.REVOKED
                    device.save()
                    messages.success(request, f"Certificate for {device.mac} has been revoked.")
                else:
                    print("CA revoke error:", ca_response.status_code, ca_response.text)
                    messages.error(request, f"Failed to revoke certificate: {ca_response.text}")
            
            elif action == "Re-issue":
                if not device.state == State.REVOKED:
                    msg = f"Device {device.mac} has not been revoked"
                    if device.certificate:
                        msg = msg + "and currently has a certificate."
                    else:
                        msg = msg + "."
                    messages.error(request, msg)
                elif device.certificate:
                    messages.error(request, f"Device {device.mac} currently has a certificate.")
                
                else:
                    return redirect("/ownership-challenge/" + device_id)


            return redirect("view_device")
        except (ValueError, Device.DoesNotExist):
            messages.error(request, f"Could not find device.")
    
    return render(request, 'view-device.html', {'devices': devices, "state_choices": State.CHOICES})

def logout_view(request):
    logout(request)
    return redirect("index")