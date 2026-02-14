from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path('verify-qr/', views.verify_qr, name='verify_qr'),
    path('enter-otp/', views.enter_otp, name="enter_otp"),
    path('select-device/', views.select_device, name="select_device"),
    path('receive-device-data/', views.receive_device_data, name="receive_device_data"),
    path('report/', views.report_device, name="report_device"),
    path('reconnect/<str:mac_address>/', views.reconnect_device, name="reconnect_device"),
    path('temp-list-devices/', views.temp_list_devices, name='temp_list_devices'),
    path('download-cert/<str:mac_address>/', views.download_cert, name="download_cert"),
    path('ownership-challenge/<int:device_id>/', views.ownership_challenge, name="ownership_challenge"),
    path('start-challenge/<int:device_id>/', views.start_challenge, name="start_challenge"),
    path('check-status/<int:device_id>/', views.check_status, name="check_status"),
]