from django.urls import path

from .views import views_data, views_device, views_ra

urlpatterns = [
    path("", views_ra.index, name="index"),
    path('verify-qr/', views_ra.verify_qr, name='verify_qr'),
    path('enter-otp/', views_ra.enter_otp, name="enter_otp"),
    path('select-device/', views_ra.select_device, name="select_device"),
    path('view-device/', views_ra.view_device, name="view_device"),
    path('logout-view/', views_ra.logout_view, name="logout_view"),
    path('ownership-challenge/<int:device_id>/', views_ra.ownership_challenge, name="ownership_challenge"),
    path('start-challenge/<int:device_id>/', views_ra.start_challenge, name="start_challenge"),
    path('check-status/<int:device_id>/', views_ra.check_status, name="check_status"),

    path('receive-device-data/', views_device.receive_device_data, name="receive_device_data"),
    path('download-cert/<str:mac_address>/', views_device.download_cert, name="download_cert"),
    path('renew-cert/<str:mac_address>/', views_device.renew_cert, name="renew_cert"),

    path('report/', views_data.report_device, name="report_device"),
    path('reconnect/<str:mac_address>/', views_data.reconnect_device, name="reconnect_device"),
]