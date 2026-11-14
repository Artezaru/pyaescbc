import ast
import os
import pathlib

import pytest
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pyaescbc._common.aes_cbc import encrypt_AES_CBC, decrypt_AES_CBC
from pyaescbc._common.auth_error import AuthError
from pyaescbc._common.bundle import join_bundle, split_bundle
from pyaescbc._common.delete_bytearray import delete_bytearray
from pyaescbc._common.etm import encrypt_then_mac, verify_then_decrypt
from pyaescbc._common.formats import bundle_kind
from pyaescbc._common.kdf import hkdf_expand_pair
from pyaescbc._common.mac import check_hmac
from pyaescbc._common.random import random_bytearray, random_iv

PACKAGE = pathlib.Path(__file__).resolve().parents[1] / "pyaescbc"


# ----------------------------------------------------------------------
# Dependency direction: _common <- modes, never mode <-> mode
# ----------------------------------------------------------------------

def _relative_imports(directory):
    for path in (PACKAGE / directory).glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.ImportFrom) and node.level > 0:
                yield path.name, node.level, node.module or ""


def test_common_depends_on_no_mode():
    for name, level, module in _relative_imports("_common"):
        assert level == 1, f"_common/{name} imports outside _common: {'.' * level}{module}"


@pytest.mark.parametrize("mode, other", [("_password_mode", "_key_mode"), ("_key_mode", "_password_mode")])
def test_modes_do_not_depend_on_each_other(mode, other):
    for name, level, module in _relative_imports(mode):
        assert other not in module, f"{mode}/{name} imports {other}"
        if level == 2:
            assert module.startswith("_common"), f"{mode}/{name} imports ..{module}"


# ----------------------------------------------------------------------
# AES-CBC: identical to the reference cryptography padding + CBC
# ----------------------------------------------------------------------

@pytest.mark.parametrize("size", range(0, 70))
def test_aes_cbc_matches_cryptography(size):
    key, iv, data = bytearray(os.urandom(32)), bytearray(os.urandom(16)), bytearray(os.urandom(size))
    padder = padding.PKCS7(128).padder()
    encryptor = Cipher(algorithms.AES(bytes(key)), modes.CBC(bytes(iv))).encryptor()
    reference = encryptor.update(padder.update(bytes(data)) + padder.finalize()) + encryptor.finalize()
    cipherdata = encrypt_AES_CBC(data, key, iv)
    assert bytes(cipherdata) == reference
    assert decrypt_AES_CBC(cipherdata, key, iv) == data


# ----------------------------------------------------------------------
# Generic bundle layout
# ----------------------------------------------------------------------

def test_join_and_split():
    header, tag, cipherdata = bytearray(b"H" * 21), bytearray(b"T" * 32), bytearray(b"C" * 32)
    bundle = join_bundle(header, tag, cipherdata)
    assert split_bundle(bundle, 21) == (header, tag, cipherdata)


@pytest.mark.parametrize("length, message", [(21 + 32 + 15, "too short"), (21 + 32 + 17, "multiple of 16")])
def test_split_errors(length, message):
    with pytest.raises(ValueError, match=message):
        split_bundle(bytearray(length), 21)


def test_join_errors():
    with pytest.raises(ValueError):
        join_bundle(bytearray(), bytearray(32), bytearray(16))
    with pytest.raises(ValueError):
        join_bundle(bytearray(1), bytearray(31), bytearray(16))
    with pytest.raises(ValueError):
        join_bundle(bytearray(1), bytearray(32), bytearray(0))


def test_bundle_kind():
    assert bundle_kind(bytearray(b"PACB....")) == "password"
    assert bundle_kind(bytearray(b"PACK....")) == "key"
    assert bundle_kind(bytearray(b"XXXX....")) is None
    assert bundle_kind(bytearray(b"PA")) is None


# ----------------------------------------------------------------------
# Encrypt-then-MAC
# ----------------------------------------------------------------------

@pytest.fixture
def sealed():
    key_material, iv = bytearray(os.urandom(64)), random_iv()
    header = bytearray(b"HDR") + iv
    tag, cipherdata = encrypt_then_mac(bytearray(b"secret"), key_material, iv, header, authdata=bytearray(b"ad"))
    return key_material, iv, header, tag, cipherdata


def test_etm_roundtrip(sealed):
    key_material, iv, header, tag, cipherdata = sealed
    assert verify_then_decrypt(header, tag, cipherdata, key_material, iv, authdata=bytearray(b"ad")) == b"secret"
    assert len(key_material) == 64        # not modified


@pytest.mark.parametrize("what", ["header", "tag", "cipherdata", "authdata", "key"])
def test_etm_detects_any_change(sealed, what):
    key_material, iv, header, tag, cipherdata = sealed
    header, tag, cipherdata, key_material = header.copy(), tag.copy(), cipherdata.copy(), key_material.copy()
    authdata = bytearray(b"ad")
    # for "key", flip a byte of the HMAC key (key_material[32:]): the two sub-keys are always
    # derived together, a wrong HMAC key is what a wrong password or key produces
    target = {"header": header, "tag": tag, "cipherdata": cipherdata, "authdata": authdata, "key": key_material}[what]
    target[40 if what == "key" else 0] ^= 1
    with pytest.raises(AuthError, match="custom message"):
        verify_then_decrypt(header, tag, cipherdata, key_material, iv, authdata=authdata,
                            error_message="custom message")


def test_etm_key_material_length():
    with pytest.raises(ValueError, match="64 bytes"):
        encrypt_then_mac(bytearray(b"x"), bytearray(32), random_iv(), bytearray(b"H"))


# ----------------------------------------------------------------------
# Utilities
# ----------------------------------------------------------------------

def test_hkdf_expand_pair_checks():
    assert len(hkdf_expand_pair(bytes(32), b"a", b"b")) == 64
    with pytest.raises(ValueError):
        hkdf_expand_pair(bytes(31), b"a", b"b")
    with pytest.raises(ValueError):
        hkdf_expand_pair(bytes(32), b"same", b"same")
    with pytest.raises(TypeError):
        hkdf_expand_pair("x" * 32, b"a", b"b")


def test_delete_bytearray():
    data = bytearray(b"secret")
    delete_bytearray(data)
    assert data == bytearray()


def test_delete_bytearray_with_open_memoryview():
    data = bytearray(b"secret")
    view = memoryview(data)
    delete_bytearray(data)                 # must not raise
    assert data == bytes(6)                # zeroed even though it cannot be resized
    view.release()


def test_random_bytearray_rejects_bool():
    assert len(random_bytearray(5)) == 5
    with pytest.raises(TypeError):
        random_bytearray(True)


def test_error_messages_never_contain_values():
    with pytest.raises(ValueError) as error:
        check_hmac(bytearray(b"SECRET-TAG"), bytearray(32))
    assert "SECRET" not in str(error.value)
