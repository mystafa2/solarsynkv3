import json
import time
from hashlib import md5


def get_nonce():
    return int(time.time() * 1000)


def _build_pem_public_key(public_key_value: str) -> bytes:
    """Normalize API public key response into valid PEM bytes."""
    key = (public_key_value or "").strip().replace("\\r", "")

    if "-----BEGIN PUBLIC KEY-----" in key:
        normalized = key.replace("\\n", "\n")
    else:
        key_body = key.replace("\\n", "").replace("\n", "")
        normalized = (
            "-----BEGIN PUBLIC KEY-----\n"
            f"{key_body}\n"
            "-----END PUBLIC KEY-----\n"
        )

    return normalized.encode("utf-8")


def gettoken():
    import base64
    import hashlib
    import requests
    from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    BearerToken = ""

    class ConsoleColor:
        OKGREEN = "\033[32m"
        FAIL = "\033[31m"
        ENDC = "\033[0m"

    with open('/data/options.json') as options_file:
        json_settings = json.load(options_file)

    source = "elinter" if json_settings["API_Server"] == "pv.inteless.com" else "sunsynk"

    public_key_nonce = get_nonce()
    public_key_signature_input = f"nonce={public_key_nonce}&source={source}POWER_VIEW"
    public_key_signature = hashlib.md5(public_key_signature_input.encode()).hexdigest()

    try:
        response = requests.get(
            f'https://{json_settings["API_Server"]}/anonymous/publicKey',
            params={
                'source': source,
                'nonce': public_key_nonce,
                'sign': public_key_signature
            },
            timeout=15,
        )
        response.raise_for_status()
        public_key_payload = response.json()
    except requests.exceptions.RequestException as e:
        print(ConsoleColor.FAIL + f"Error: Failed to retrieve public key from Sunsynk API. {e}" + ConsoleColor.ENDC)
        return BearerToken
    except json.JSONDecodeError:
        print(ConsoleColor.FAIL + "Error: Failed to parse public key response from Sunsynk API." + ConsoleColor.ENDC)
        return BearerToken

    public_key_string = public_key_payload.get('data', '') if isinstance(public_key_payload, dict) else ''
    if not isinstance(public_key_string, str) or not public_key_string.strip():
        print(ConsoleColor.FAIL + "Error: Sunsynk API returned an empty/invalid public key." + ConsoleColor.ENDC)
        return BearerToken

    try:
        public_key = load_pem_public_key(_build_pem_public_key(public_key_string))
    except ValueError as e:
        print(ConsoleColor.FAIL + f"Error: Could not decode public key returned by API. {e}" + ConsoleColor.ENDC)
        return BearerToken

    encrypted_password = base64.b64encode(public_key.encrypt(
        json_settings['sunsynk_pass'].encode('utf-8'),
        padding=PKCS1v15()
    )).decode('utf-8')

    token_nonce = get_nonce()
    token_sign_string = f'nonce={token_nonce}&source={source}{public_key_string[:10]}'
    token_sign = md5(token_sign_string.encode()).hexdigest()

    url = f'https://{json_settings["API_Server"]}/oauth/token/new'
    payload = {
        "client_id": "csp-web",
        "grant_type": "password",
        "password": encrypted_password,
        "source": source,
        "username": json_settings['sunsynk_user'],
        'nonce': token_nonce,
        'sign': token_sign
    }

    headers = {"Content-Type": "application/json"}
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        response.raise_for_status()
        parsed_login_json = response.json()

        if parsed_login_json.get('msg') == "Success":
            print("Sunsynk Login: " + ConsoleColor.OKGREEN + parsed_login_json['msg'] + ConsoleColor.ENDC)
            BearerToken = parsed_login_json['data']['access_token']
            return BearerToken

        print("Sunsynk Login: " + ConsoleColor.FAIL + parsed_login_json.get('msg', 'Unknown error') + ConsoleColor.ENDC)
        return BearerToken

    except requests.exceptions.Timeout:
        print(ConsoleColor.FAIL + "Error: Request timed out while connecting to Sunsynk API." + ConsoleColor.ENDC)
        return BearerToken
    except requests.exceptions.RequestException as e:
        print(ConsoleColor.FAIL + f"Error: Failed to connect to Sunsynk API. {e}" + ConsoleColor.ENDC)
        return BearerToken
    except json.JSONDecodeError:
        print(ConsoleColor.FAIL + "Error: Failed to parse Sunsynk API response." + ConsoleColor.ENDC)
        return BearerToken
