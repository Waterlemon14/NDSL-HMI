from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path('verify-qr/', views.verify_qr, name='verify_qr'),
    path('enter-otp/', views.enter_otp, name="enter_otp"),
    path('select-device/', views.select_device, name="select_device"),
    path('receive-device-data/', views.receive_device_data, name="receive_device_data"),
    path('download-cert/<str:mac_address>/', views.download_cert),
]