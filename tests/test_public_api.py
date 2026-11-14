import warnings

import pytest

import pyaescbc

PUBLIC = {
    "__version__",
    "encrypt", "decrypt", "DEFAULT_ITERATIONS", "MIN_ITERATIONS", "MAX_ITERATIONS",
    "encrypt_with_key", "decrypt_with_key", "generate_key", "KEY_SIZE",
    "AuthError", "delete_bytearray",
}

DEPRECATED = [
    "cleardata_to_encrypted_bundle", "encrypted_bundle_to_cleardata", "derive_key",
    "create_bundle_header", "create_encrypted_bundle", "extract_cryptography_components",
    "BundleComponents", "create_hmac", "check_hmac",
    "random_bytearray", "random_iv", "random_salt",
]

FAST = pyaescbc.MIN_ITERATIONS


def test_all_is_exactly_the_public_api():
    # Adding a public name must be a deliberate decision: update this test.
    assert set(pyaescbc.__all__) == PUBLIC
    assert len(pyaescbc.__all__) == len(PUBLIC)


def test_public_names_exist_without_warning():
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        for name in PUBLIC:
            getattr(pyaescbc, name)


def test_dir_shows_only_the_public_api():
    assert set(dir(pyaescbc)) == PUBLIC


@pytest.mark.parametrize("name", DEPRECATED)
def test_deprecated_names_still_work_with_a_warning(name):
    with pytest.warns(DeprecationWarning, match=name):
        assert getattr(pyaescbc, name) is not None


def test_deprecated_functions_behave_as_before():
    with pytest.warns(DeprecationWarning):
        old_encrypt = pyaescbc.cleardata_to_encrypted_bundle
    bundle = old_encrypt(bytearray(b"x"), bytearray(b"pw"), iterations=FAST)
    assert pyaescbc.decrypt(bundle, bytearray(b"pw")) == b"x"


@pytest.mark.parametrize("name", ["expand_key", "encrypt_AES_CBC", "hkdf_expand_pair", "nope"])
def test_internal_names_are_not_exposed(name):
    with pytest.raises(AttributeError):
        getattr(pyaescbc, name)


def test_aliases_target_the_internal_functions():
    from pyaescbc._password_mode.cleardata_to_encrypted_bundle import cleardata_to_encrypted_bundle
    from pyaescbc._key_mode.key_bundle_to_cleardata import key_bundle_to_cleardata
    assert pyaescbc.encrypt is cleardata_to_encrypted_bundle
    assert pyaescbc.decrypt_with_key is key_bundle_to_cleardata


@pytest.mark.parametrize("function", ["encrypt", "decrypt", "encrypt_with_key", "decrypt_with_key"])
def test_authdata_is_keyword_only(function):
    import inspect
    parameter = inspect.signature(getattr(pyaescbc, function)).parameters["authdata"]
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY


# ----------------------------------------------------------------------
# The two modes can never be confused
# ----------------------------------------------------------------------

def test_password_bundle_rejected_by_key_mode():
    bundle = pyaescbc.encrypt(bytearray(b"x"), bytearray(b"pw"), iterations=FAST)
    with pytest.raises(ValueError, match="password-mode bundle, use decrypt"):
        pyaescbc.decrypt_with_key(bundle, pyaescbc.generate_key())


def test_key_bundle_rejected_by_password_mode():
    bundle = pyaescbc.encrypt_with_key(bytearray(b"x"), pyaescbc.generate_key())
    with pytest.raises(ValueError, match="key-mode bundle, use decrypt_with_key"):
        pyaescbc.decrypt(bundle, bytearray(b"pw"))


# ----------------------------------------------------------------------
# Envelope encryption: the intended use of both modes together
# ----------------------------------------------------------------------

def test_envelope_pattern():
    data_key = pyaescbc.generate_key()
    wrapped_key = pyaescbc.encrypt(data_key.copy(), bytearray(b"password"), iterations=FAST)
    secrets = [
        pyaescbc.encrypt_with_key(bytearray(f"secret {i}", "utf-8"), data_key,
                                  authdata=bytearray(f"entry={i}", "utf-8"))
        for i in range(50)
    ]

    session_key = pyaescbc.decrypt(wrapped_key, bytearray(b"password"))
    assert session_key == data_key
    for i, bundle in enumerate(secrets):
        assert pyaescbc.decrypt_with_key(bundle, session_key, authdata=bytearray(f"entry={i}", "utf-8")) \
            == bytearray(f"secret {i}", "utf-8")

    rewrapped = pyaescbc.encrypt(session_key.copy(), bytearray(b"new password"), iterations=FAST)
    with pytest.raises(pyaescbc.AuthError):
        pyaescbc.decrypt(rewrapped, bytearray(b"password"))
    assert pyaescbc.decrypt(rewrapped, bytearray(b"new password")) == data_key
