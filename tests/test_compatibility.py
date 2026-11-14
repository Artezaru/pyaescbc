"""
Bundles produced by pyaescbc 2.1.0 (before the reorganisation into _common / _password_mode /
_key_mode). They must ALWAYS decrypt: if this test fails, existing user files are broken.
"""
import pytest

import pyaescbc

V2_1_BUNDLE = bytes.fromhex(
    "5041434202000186a0ec5f709bf58d951098b02e1c59b7b41467ed98d1fb79798ad68038482fe585c56a5ea8"
    "722f4556a62f9da92a04690df3253501d529a2ff9f4bae9e28bc4c432cca13b25cef4839a5603bb28c9c19e1"
    "981b99678313a63ae25e2ebc1394e4419d96be7f364a7ef6014cc4ccd72b0e98c4"
)
V2_1_EMPTY_WITH_AUTHDATA = bytes.fromhex(
    "5041434202000186a082eeb84d47cbd94618662acc1a2f67834310ab990e596b7f0c9eeb71d1fce0b07341a5"
    "1fd12b1e790e4196ae59a5ea1fdd0d804cd3e983d8c40d874a03f2281827ea92c22d325304c08e0807325cef"
    "147412b5970aa01259a38d7766205580e3"
)


def test_decrypt_2_1_bundle():
    cleardata = pyaescbc.decrypt(bytearray(V2_1_BUNDLE), bytearray(b"correct horse battery staple"))
    assert cleardata == b"bippass legacy secret"


def test_decrypt_2_1_bundle_with_authdata():
    cleardata = pyaescbc.decrypt(
        bytearray(V2_1_EMPTY_WITH_AUTHDATA), bytearray(b"pw"), authdata=bytearray(b"entry=42")
    )
    assert cleardata == b""
    with pytest.raises(pyaescbc.AuthError):
        pyaescbc.decrypt(bytearray(V2_1_EMPTY_WITH_AUTHDATA), bytearray(b"pw"))


def test_2_1_bundle_layout_is_unchanged():
    # A new bundle has exactly the same header layout as a 2.1 bundle.
    new = pyaescbc.encrypt(bytearray(b"x" * 21), bytearray(b"pw"), iterations=100_000)
    assert new[:5] == V2_1_BUNDLE[:5]                  # magic "PACB" + version 2
    assert new[5:9] == V2_1_BUNDLE[5:9]                # iterations 100 000
    assert len(new) == len(V2_1_BUNDLE)                # same size for the same input size
