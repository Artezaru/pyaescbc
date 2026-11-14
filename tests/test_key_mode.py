import hashlib
import hmac
import struct
import time

import pytest
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

import pyaescbc
from pyaescbc._key_mode.expand_key import expand_key
from pyaescbc._key_mode.create_key_bundle import create_key_bundle_header, create_key_encrypted_bundle
from pyaescbc._key_mode.extract_key_bundle_components import extract_key_bundle_components
from pyaescbc._common.random import random_iv


def msg(text="Hello, World!"):
    return bytearray(text, "utf-8")


@pytest.fixture
def key():
    return pyaescbc.generate_key()


# ----------------------------------------------------------------------
# Keys
# ----------------------------------------------------------------------

def test_generate_key(key):
    assert isinstance(key, bytearray)
    assert len(key) == pyaescbc.KEY_SIZE == 32
    assert len({bytes(pyaescbc.generate_key()) for _ in range(50)}) == 50


def test_expand_key(key):
    key_material = expand_key(key)
    assert len(key_material) == 64
    assert key_material[:32] != key_material[32:]      # independent sub-keys
    assert expand_key(key) == key_material             # deterministic
    assert len(key) == 32                              # key not modified


def test_expand_key_is_domain_separated_from_password_mode(key):
    password_labels = (b"pyaescbc v2 aes-256-cbc key", b"pyaescbc v2 hmac-sha256 key")
    password_subkeys = b"".join(
        HKDFExpand(algorithm=hashes.SHA256(), length=32, info=label).derive(bytes(key))
        for label in password_labels
    )
    assert bytes(expand_key(key)) != password_subkeys


@pytest.mark.parametrize("bad", [b"x" * 32, "x" * 32, None])
def test_expand_key_type(bad):
    with pytest.raises(TypeError):
        expand_key(bad)


@pytest.mark.parametrize("size", [0, 16, 31, 33, 64])
def test_expand_key_length(size):
    with pytest.raises(ValueError, match="key must be 32 bytes"):
        expand_key(bytearray(size))


# ----------------------------------------------------------------------
# Round trip
# ----------------------------------------------------------------------

@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 31, 32, 1000])
def test_roundtrip(key, size):
    data = (bytearray(range(256)) * 4)[:size]
    bundle = pyaescbc.encrypt_with_key(data.copy(), key)
    assert pyaescbc.decrypt_with_key(bundle, key) == data


def test_bundle_layout(key):
    bundle = pyaescbc.encrypt_with_key(msg("x" * 20), key)   # 20 bytes -> 2 blocks
    assert bundle[:4] == b"PACK"
    assert bundle[4] == 1
    assert len(bundle) == 21 + 32 + 32
    components = extract_key_bundle_components(bundle)
    assert components.header == bundle[:21]
    assert components.iv == bundle[5:21]
    assert components.expected_hmac == bundle[21:53]
    assert components.cipherdata == bundle[53:]


def test_random_iv(key):
    a = pyaescbc.encrypt_with_key(msg(), key)
    b = pyaescbc.encrypt_with_key(msg(), key)
    assert a[5:21] != b[5:21]


def test_key_mode_is_fast(key):
    start = time.perf_counter()
    for _ in range(200):
        pyaescbc.decrypt_with_key(pyaescbc.encrypt_with_key(msg(), key), key)
    # 400 operations; a single PBKDF2 at MIN_ITERATIONS already takes ~40 ms.
    assert time.perf_counter() - start < 2.0


# ----------------------------------------------------------------------
# Wiping
# ----------------------------------------------------------------------

def test_default_wiping(key):
    key_copy, data = key.copy(), msg()
    bundle = pyaescbc.encrypt_with_key(data, key)
    assert len(data) == 0                 # cleardata wiped by default
    assert key == key_copy                # key kept by default (reused)
    bundle_copy = bundle.copy()
    pyaescbc.decrypt_with_key(bundle, key)
    assert bundle == bundle_copy          # bundle kept by default
    assert key == key_copy


def test_explicit_wiping(key):
    data = msg()
    bundle = pyaescbc.encrypt_with_key(data, key.copy(), delete_data=False, delete_keys=True)
    assert data == msg()
    used_key = key.copy()
    pyaescbc.decrypt_with_key(bundle, used_key, delete_keys=True, delete_data=True)
    assert len(used_key) == 0
    assert len(bundle) == 0


def test_failed_decryption_keeps_bundle_and_wipes_key_if_asked(key):
    bundle = pyaescbc.encrypt_with_key(msg(), key)
    wrong = pyaescbc.generate_key()
    with pytest.raises(pyaescbc.AuthError):
        pyaescbc.decrypt_with_key(bundle, wrong, delete_keys=True, delete_data=True)
    assert len(wrong) == 0
    assert len(bundle) > 0


def test_failed_encryption_keeps_cleardata():
    data = msg()
    with pytest.raises(ValueError):
        pyaescbc.encrypt_with_key(data, bytearray(16))
    assert data == msg()


# ----------------------------------------------------------------------
# Authentication
# ----------------------------------------------------------------------

def test_wrong_key(key):
    bundle = pyaescbc.encrypt_with_key(msg(), key)
    with pytest.raises(pyaescbc.AuthError, match="wrong key or authdata"):
        pyaescbc.decrypt_with_key(bundle, pyaescbc.generate_key())


def test_authdata(key):
    bundle = pyaescbc.encrypt_with_key(msg(), key, authdata=bytearray(b"item=1|field=password"))
    assert pyaescbc.decrypt_with_key(bundle, key, authdata=bytearray(b"item=1|field=password")) == msg()
    for wrong in (None, bytearray(), bytearray(b"item=2|field=password")):
        with pytest.raises(pyaescbc.AuthError):
            pyaescbc.decrypt_with_key(bundle, key, authdata=wrong)


def test_authdata_not_modified(key):
    authdata = bytearray(b"context")
    bundle = pyaescbc.encrypt_with_key(msg(), key, authdata=authdata)
    pyaescbc.decrypt_with_key(bundle, key, authdata=authdata)
    assert authdata == bytearray(b"context")


@pytest.mark.parametrize("offset", [5, 20, 21, 52, 53, -1])   # iv, hmac, cipherdata
def test_tampering_is_detected(key, offset):
    bundle = pyaescbc.encrypt_with_key(msg(), key)
    bundle[offset] ^= 0x01
    with pytest.raises(pyaescbc.AuthError):
        pyaescbc.decrypt_with_key(bundle, key)


@pytest.mark.parametrize("offset", [0, 3, 4])                # magic, version
def test_header_tampering_is_rejected(key, offset):
    bundle = pyaescbc.encrypt_with_key(msg(), key)
    bundle[offset] ^= 0x01
    with pytest.raises(ValueError):
        pyaescbc.decrypt_with_key(bundle, key)


# ----------------------------------------------------------------------
# Malformed bundles / arguments
# ----------------------------------------------------------------------

@pytest.mark.parametrize("cut", [1, 15, 16, 40])
def test_truncated(key, cut):
    bundle = pyaescbc.encrypt_with_key(msg(), key)
    with pytest.raises(ValueError):
        pyaescbc.decrypt_with_key(bundle[:-cut], key)


def test_too_short(key):
    for data in (bytearray(b"PACK\x01"), bytearray()):
        with pytest.raises(ValueError, match="too short"):
            pyaescbc.decrypt_with_key(data, key)


@pytest.mark.parametrize(
    "call",
    [
        lambda k: pyaescbc.encrypt_with_key(b"bytes", k),
        lambda k: pyaescbc.encrypt_with_key(msg(), bytes(k)),
        lambda k: pyaescbc.encrypt_with_key(msg(), k, authdata=b"bytes"),
        lambda k: pyaescbc.encrypt_with_key(msg(), k, delete_keys=1),
        lambda k: pyaescbc.encrypt_with_key(msg(), k, delete_data="yes"),
        lambda k: pyaescbc.encrypt_with_key(msg(), k, bytearray(b"positional authdata")),
        lambda k: pyaescbc.decrypt_with_key(b"bytes", k),
        lambda k: pyaescbc.decrypt_with_key(bytearray(69), bytes(k)),
        lambda k: pyaescbc.decrypt_with_key(bytearray(69), k, authdata="x"),
        lambda k: pyaescbc.decrypt_with_key(bytearray(69), k, delete_keys=None),
    ],
)
def test_type_errors(key, call):
    with pytest.raises(TypeError):
        call(key)


def test_header_builders():
    iv = random_iv()
    header = create_key_bundle_header(iv)
    assert header == bytearray(b"PACK\x01") + iv
    with pytest.raises(ValueError):
        create_key_bundle_header(bytearray(15))
    with pytest.raises(ValueError):
        create_key_encrypted_bundle(bytearray(21), bytearray(32), bytearray(16))   # bad magic
    with pytest.raises(ValueError):
        create_key_encrypted_bundle(header, bytearray(31), bytearray(16))
    with pytest.raises(ValueError):
        create_key_encrypted_bundle(header, bytearray(32), bytearray(15))
    with pytest.raises(TypeError):
        create_key_encrypted_bundle(bytearray(21), b"x" * 32, bytearray(16))     # types first


def test_unsupported_version(key):
    bundle = pyaescbc.encrypt_with_key(msg(), key)
    bundle[4] = 9
    with pytest.raises(ValueError, match="unsupported version 9"):
        pyaescbc.decrypt_with_key(bundle, key)


# ----------------------------------------------------------------------
# Specification: an independent implementation of the documented format
# ----------------------------------------------------------------------

def _reference_encrypt(cleardata: bytes, key: bytes, iv: bytes, authdata: bytes = b"") -> bytes:
    """Build a key-mode bundle from the documentation only, with cryptography directly."""
    aes_key = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"pyaescbc key-mode v1 aes-256-cbc key").derive(key)
    hmac_key = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"pyaescbc key-mode v1 hmac-sha256 key").derive(key)
    padder = padding.PKCS7(128).padder()
    encryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv)).encryptor()
    cipherdata = encryptor.update(padder.update(cleardata) + padder.finalize()) + encryptor.finalize()
    header = b"PACK" + bytes([1]) + iv
    mac = hmac.new(hmac_key, digestmod=hashlib.sha256)
    for field in (header, cipherdata, authdata):
        mac.update(struct.pack(">Q", len(field)))
        mac.update(field)
    return header + mac.digest() + cipherdata


def test_matches_the_documented_format(key):
    authdata = b"ctx"
    reference = bytearray(_reference_encrypt(b"Hello, World!", bytes(key), bytes(range(16)), authdata))
    assert pyaescbc.decrypt_with_key(reference, key, authdata=bytearray(authdata)) == msg()
    bundle = pyaescbc.encrypt_with_key(msg(), key, authdata=bytearray(authdata))
    assert bytes(bundle) == _reference_encrypt(b"Hello, World!", bytes(key), bytes(bundle[5:21]), authdata)
