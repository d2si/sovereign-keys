# Copyright 2022 Devoteam Revolve (D2SI SAS)
# This file is part of `Sovereign Keys`.
#
# `Sovereign Keys` is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# `Sovereign Keys` is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with `Sovereign Keys`. If not, see <http://www.gnu.org/licenses/>.

import time
import os
from threading import Lock
from utils import logger, extract_modulus_and_exp_from_der, HTTPError

##########
# CONSTS #
##########
PKCS11_LIB = '/opt/cloudhsm/lib/libcloudhsm_pkcs11.so'
SLOT=None # Use it only if you want to force a particular SLOT number. Else we will just use the first avalable
DOMAIN_KEY_LABEL = 'domain_key'
SIGNATURE_PRIV_KEY_LABEL = 'sig_key'
SIGNATURE_PUB_KEY_LABEL = 'sig_key_pub'

###########
# GLOBALS #
###########
_DOMAIN_KEY_HANDLE = None
_SIGNATURE_KEY_HANDLES = None
_PIN = None
_pin_lock = Lock()

####################
# HSM interactions #
####################
from skpkcs11 import CloudHSMLib, Mechanism, KeyType
import skpkcs11.vendordefinedconstants.cloudhsm as cloudhsm_constants

_p_lib = CloudHSMLib.get_instance(PKCS11_LIB)
_token = None
def open_token_session(pin=None):
    session_pin = _PIN if pin is None else pin
    global _token
    if _token is None:
        _token = _p_lib.get_token(SLOT)
    return _token.session(pin=session_pin)

# Test connexion with the HSM
def test_cloudhsm_connection(pin=None):
    if pin is None:
        pin = _PIN
    if pin is None:
        raise Exception('PIN is not set')
    with open_token_session(pin=pin) as session:
        infos = session.get_session_info()
        logger.debug(f'Session Infos: {infos}')

def cloudhsm_set_pin(pin):
    global _PIN
    with _pin_lock:
        test_cloudhsm_connection(pin)
        _PIN = pin
        logger.info('PIN accepted')

# Retrieve the handle of the domain key
def get_domain_key_handle():
    global _DOMAIN_KEY_HANDLE
    logger.info(f'Retrieving KEY_HANDLE for key {DOMAIN_KEY_LABEL}')
    with open_token_session() as session:
        _DOMAIN_KEY_HANDLE = session.get_object_handle(label=DOMAIN_KEY_LABEL)
        if _DOMAIN_KEY_HANDLE == 0:
            logger.info(f'Key {DOMAIN_KEY_LABEL} does not exist and must be created')
            # The key does not exist, creates it
            _DOMAIN_KEY_HANDLE = session.create_secret_key(
                key_label=DOMAIN_KEY_LABEL,
                key_gen_mech=Mechanism.AES_KEY_GEN,
                key_size_in_bits=256,
                token=True,         # The key is resident in the token
                private=True,       # It is not visible if not logged-in
                sensitive=True,     # It cannot be exported in cleartext
                modifiable=False,   # We don't modify it
                extractable=False,  # We cannot export it at all
                sign=False,         # We cannot sign
                verify=False,       # We cannot verify signatures
                encrypt=False,      # We cannot encrypt
                decrypt=False,      # We cannot decrypt
                wrap=False,         # We cannot wrap
                unwrap=False,       # We cannot unwrap
                derive=True         # We can only derive
            )
    if _DOMAIN_KEY_HANDLE == 0:
        logger.error(f'Could not find nor create key {DOMAIN_KEY_LABEL}')
        raise Exception('Failed to retrieve or create the Domain Key')
    logger.debug(f'Key {DOMAIN_KEY_LABEL} handle is {_DOMAIN_KEY_HANDLE}')
    return _DOMAIN_KEY_HANDLE

# Retrieve the handles of the sig keys
def _get_signature_key_handles():
    global _SIGNATURE_KEY_HANDLES
    logger.info(f'Retrieving KEY_HANDLES for keys {SIGNATURE_PRIV_KEY_LABEL} and {SIGNATURE_PUB_KEY_LABEL}')
    with open_token_session() as session:
        priv_h = session.get_object_handle(label=SIGNATURE_PRIV_KEY_LABEL)
        if priv_h == 0:
            logger.info(f'Key {SIGNATURE_PRIV_KEY_LABEL} does not exist and must be created')
            # The key does not exist, creates it
            pub_h, priv_h = session.create_ec_key_pair(
                private_key_label=SIGNATURE_PRIV_KEY_LABEL,
                public_key_label=SIGNATURE_PUB_KEY_LABEL,
                token=True,         # The key pair is resident in the token
                private=True,       # It is not visible if not logged-in
                modifiable=False,   # We don't modify it
                extractable=False,  # We cannot export it at all
                sensitive=True      # It cannot be exported in cleartext
            )
        else:
            pub_h = session.get_object_handle(label=SIGNATURE_PUB_KEY_LABEL)
    if priv_h == 0:
        logger.error(f'Could not find nor create key {SIGNATURE_PRIV_KEY_LABEL}')
        raise Exception('Failed to retrieve or create the Sig Key')
    if pub_h == 0:
        logger.error(f'Could not find key {SIGNATURE_PUB_KEY_LABEL}')
        raise Exception('Failed to retrieve the public Sig Key')
    _SIGNATURE_KEY_HANDLES = (pub_h, priv_h)
    logger.debug(f'Keys ({SIGNATURE_PUB_KEY_LABEL},{SIGNATURE_PRIV_KEY_LABEL}) handles are {_SIGNATURE_KEY_HANDLES}')
    return _SIGNATURE_KEY_HANDLES

def get_signature_priv_key_handle():
    priv = _get_signature_key_handles()[1]
    logger.debug(f'Key {SIGNATURE_PRIV_KEY_LABEL} handle is {priv}')
    return priv

def get_signature_pub_key_handle():
    pub = _get_signature_key_handles()[0]
    logger.debug(f'Key {SIGNATURE_PUB_KEY_LABEL} handle is {pub}')
    return pub

# Generic derivation, derive+wrap and derive+unwrap
def _derive_kek(session, key_handle, nonce):
    return session.derive_master_key(
        base_key_handle=key_handle,
        derive_key_mech=(
            Mechanism.VENDOR_DEFINED
            | cloudhsm_constants.Mechanism.SP800_108_COUNTER_KDF
        ),
        nonce=nonce,
        key_label='tmp_derived_secret',
        key_type=KeyType.AES,
        key_size_in_bits=256,
        token=True,        # session key (wiped when session is closed)
        private=True,       # It is not visible if not logged-in
        sensitive=True,     # It cannot be exported in cleartext
        modifiable=True,    # We don't modify it
        extractable=True,   # Apparently we cannot use "False" for some reason
        sign=True,          # We can sign (mandatory for AES-GCM)
        verify=True,        # We can verify (mandatory for AES-GCM)
        encrypt=False,      # We cannot encrypt
        decrypt=False,      # We cannot decrypt
        wrap=True,          # We can wrap
        unwrap=True,        # We can unwrap
        derive=False        # We cannot derive
    )

def cloudhsm_derive_kek_and_wrap(session, wrapping_key_handle, secret_handle, aad):
    logger.debug(f'HSM: Exporting secret (handle: {secret_handle}) wrapped with AES256 key derived from key (handle: {wrapping_key_handle})')
    # Generate a random 256-bits Nonce
    logger.debug('HSM: Generate Nounce (256bits)')
    nonce = session.generate_random(size=32)
    # Derive a KEK from the existing key
    derived_key_handle = _derive_kek(session, wrapping_key_handle, nonce)
    logger.debug(f'HSM: Temporary derived key created from key (handle: {derived_key_handle})')
    # Use the derived KEK to wrap the secret
    try:
        iv, wrapped_secret_bytes = session.wrap_key_sym(
            key_handle=secret_handle,
            wrap_key_handle=derived_key_handle,
            wrap_key_mech=Mechanism.AES_GCM,
            aad=aad
        )
    finally:
        cloudhsm_delete_object(session, derived_key_handle)
    # We return a concatenated blob of iv, nonce and wrapped secret
    return iv + nonce + wrapped_secret_bytes

def cloudhsm_derive_kek_and_unwrap(session, wrapping_key_handle, cipher_text, aad, target_key_type, extractable):
    logger.debug(f'HSM: Importing secret wrapped with AES256 key derived from key (handle: {wrapping_key_handle})')
    logger.debug('HSM: Extracting IV (96 bits) and Nounce (256bits) from cyphertext')
    # Retrieve IV, Nonce and wrapped secret from the cipher_text
    iv = cipher_text[:12]
    nonce = cipher_text[12:44]
    wrapped_secret_bytes = cipher_text[44:]
    # Re-derive the KEK using the retrieved Nonce
    derived_key_handle = _derive_kek(session, wrapping_key_handle, nonce)
    logger.debug(f'HSM: Temporary derived key created from key (handle: {derived_key_handle})')
    # Use the derived KEK to unwrap the secret
    try:
        secret_h = session.unwrap_key_sym(
            wrap_key_handle=derived_key_handle,
            wrap_key_mech=Mechanism.AES_GCM,
            wrap_key_iv=iv,
            aad=aad,
            key_label="tmp_secret",
            key_data=wrapped_secret_bytes,
            key_type=target_key_type,
            token=True,
            private=True,
            sensitive=True,
            modifiable=True,
            extractable=extractable,
            sign=False,
            verify=False,
            encrypt=False,
            decrypt=False,
            wrap=False,
            unwrap=False,
            derive=True
        )
    except:
        logger.exception('Incorrect AAD or wrapped secret ?')
        raise HTTPError(400, 'Wrapped secret and/or context are incorrect')
    finally:
        # Cleanup
        cloudhsm_delete_object(session, derived_key_handle)
    logger.debug(f'HSM: Secret handle: {secret_h}')
    # Return the unwraped secret handle for futur manipulation in the session
    return secret_h

# Generate new CMK
def cloudhsm_generate_new_cmk(session):
    logger.debug('HSM: Generating a new CMK')
    # Generate a new AES key
    logger.debug('HSM: Create AES key')
    cmk_h = session.create_secret_key(
        key_label='tmp_cmk',
        key_gen_mech=Mechanism.AES_KEY_GEN,
        key_size_in_bits=256,
        token=True,        # session key (wiped when session is closed)
        private=True,       # It is not visible if not logged-in
        sensitive=True,     # It cannot be exported in cleartext
        modifiable=False,   # We don't modify it
        extractable=True,   # We need to export it
        sign=False,         # No capabilities, we will just export it
        verify=False,       # No capabilities, we will just export it
        encrypt=False,      # No capabilities, we will just export it
        decrypt=False,      # No capabilities, we will just export it
        wrap=False,         # No capabilities, we will just export it
        unwrap=False,       # No capabilities, we will just export it
        derive=False        # No capabilities, we will just export it
    )
    logger.debug(f'HSM: CMK AES key handle {cmk_h}')
    return cmk_h

# Import RSA pub key
def cloudhsm_import_rsa_public_key(session, rsa_pub_key):
    logger.debug('HSM: Importing RSA public key')
    try:
        mod, exp = extract_modulus_and_exp_from_der(rsa_pub_key)
    except:
        logger.exception('Invalid RSA pub key')
        raise HTTPError(400, 'Invalid RSA pub key')
    rsa_pub_h = session.import_rsa_public_key(
        key_label='tmp_rsa',
        modulus=mod,
        exponent=exp,
        token=True,
        private=True,
        modifiable=True,
        verify=False,
        encrypt=False,
        wrap=True
    )
    logger.debug(f'HSM: RSA Pub key handle: {rsa_pub_h}')
    return rsa_pub_h

# Secret generation/wraping/import/export
def cloudhsm_generate_new_secret(session):
    logger.debug('HSM: Generating a new GENERIC secret')
    # Generate a generic secret
    secret_h = session.create_secret_key(
        key_label='tmp_secret',
        key_gen_mech=Mechanism.GENERIC_SECRET_KEY_GEN,
        key_size_in_bits=256,
        token=True,
        private=True,
        sensitive=True,
        modifiable=True,
        extractable=True,
        sign=False,
        verify=False,
        encrypt=False,
        decrypt=False,
        wrap=False,
        unwrap=False,
        derive=True
    )
    logger.debug(f'HSM: New secret handle: {secret_h}')
    return secret_h

def cloudhsm_wrap_secret_rsa(session, pub_key_handle, secret_handle):
    logger.debug(f'HSM: Wrapping secret (handle: {secret_handle}) with RSA key (handle: {pub_key_handle})')
    # Generate a random IV
    # iv = session.generate_random(size=16) # Useless since we cannot use it in openssl on the client side
    wrapped_secret_bytes = session.wrap_key_asym(
        key_handle=secret_handle,
        wrap_key_handle=pub_key_handle,
        wrap_key_mech=Mechanism.RSA_PKCS_OAEP
    )
    return wrapped_secret_bytes

def cloudhsm_delete_object(session, handle):
    logger.debug(f'HSM: Deleting object handle: {handle}')
    session.destroy_object(object_handle=handle)
