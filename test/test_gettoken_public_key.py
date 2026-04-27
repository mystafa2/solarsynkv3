from gettoken import _build_pem_public_key


def test_build_pem_public_key_from_raw_base64():
    raw = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArandomkeydata"
    pem = _build_pem_public_key(raw).decode("utf-8")

    assert pem.startswith("-----BEGIN PUBLIC KEY-----\n")
    assert pem.endswith("\n-----END PUBLIC KEY-----\n")
    assert raw in pem


def test_build_pem_public_key_from_full_pem_with_escaped_newlines():
    escaped = "-----BEGIN PUBLIC KEY-----\\nAAAABBBB\\n-----END PUBLIC KEY-----"
    pem = _build_pem_public_key(escaped).decode("utf-8")

    assert "-----BEGIN PUBLIC KEY-----\n" in pem
    assert "\n-----END PUBLIC KEY-----" in pem
