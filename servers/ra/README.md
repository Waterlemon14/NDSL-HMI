1. Setup venv and install requirements

2. Setup mosip config & files
- config, keystore and link

2. Initialize CA, server, and other certificates
(CA directory) bash init.sh

3. Run CA's signing server
(CA directory) go run .

4. Run server and listen for requests
(verification directory) python manage.py runserver

5. Provide QR of registered user in MOSIP testbed

6. Provide OTP

7. Provide CSR