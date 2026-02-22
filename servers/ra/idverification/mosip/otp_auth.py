from mosip_auth_sdk import MOSIPAuthenticator
from dynaconf import Dynaconf
from pathlib import Path

def verify_qr(UIN):
    print("Verifying QR")
    config_path = Path(__file__).resolve().parent.parent.parent / "config.toml"
    print(config_path)
    config = Dynaconf(settings_files=[config_path], environments=False)
    authenticator = MOSIPAuthenticator(config=config)
    print("MOSIP Setup")

    # step 1: generate otp
    response = authenticator.genotp(
        individual_id=UIN,
        individual_id_type="UIN",
        # can pass either one of these
        email=True,
        phone=True,
    )
    response_body = response.json()

    print(response_body)

    return (response_body)

def verify_otp(UIN, OTP, transaction_id):
    config_path = Path(__file__).resolve().parent.parent.parent / "config.toml"
    config = Dynaconf(settings_files=[config_path], environments=False)
    authenticator = MOSIPAuthenticator(config=config)

    # step 2: use otp and transaction id in auth request
    # can change function to authenticator.kyc()
    # but don't forget to decrypt the response for that
    response = authenticator.auth(
        individual_id=UIN,
        individual_id_type="UIN",
        otp_value= OTP,
        consent=True,
        txn_id=transaction_id,
    )
    response_body = response.json()
    print(f"RESPONSE: {response_body}")

    return (response_body)
