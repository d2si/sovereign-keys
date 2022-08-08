from typing import Tuple

from utils import logger, sig_to_der
from .proteccio import *

def is_token_ready() -> bool:
    """Verify the token is usable.

    Must return True only if the token (HSM) is reachable and ready to perform
    cryptographic duties, i.e. if the correct PIN is set.

    Returns:
        True if the token is reachable and ready to perform cryptographic
        duties, False otherwise.
    """
    try:
        test_proteccio_connection()
        return True
    except:
        return False

def set_pin(pin: bytes) -> None:
    """Set the token PIN.

    Must only accept the PIN if it is the correct one, else it raises an
    exception.

    Args:
        pin: The PIN to set for opening sessions and perform
            cryptographic operations.

    Returns:
        None

    Raises:
        BadPINException: The PIN was not accepted
    """
    proteccio_set_pin(pin)

from ecdsa.keys import VerifyingKey
from ecdsa.curves import NIST384p
def export_public_signing_key() -> bytes:
    """Export the Public Signing Key.

    Export the Public part of the ECDSA KeyPair used to sign API responses and
    logs. It MUST be the Public Key part of the Key Pair used by the sign
    function.

    Returns:
        bytes: The DER encoded Public Key
    """

    with open_token_session() as session:
        attrs = session.get_attributes(
            get_signature_pub_key_handle(),
            ['ec_point']
        )
    logger.debug(f'PubKey attrs: {attrs}')
    return VerifyingKey.from_string(attrs['ec_point'][2:], curve=NIST384p).to_der()

from hashlib import sha256
def sign(blob: bytes) -> bytes:
    """Sign a blob using ECDSA.

    Args:
        blob: Data to sign.

    Returns:
        sig: The DER-encoded ECDSA signature of the blob.
    """

    logger.debug('HSM: Signing data blob')
    with open_token_session() as session:
        rs_sig = session.sign(
            get_signature_priv_key_handle(),
            Mechanism.ECDSA,
            sha256(blob).digest()
        )
    return sig_to_der(rs_sig)

def create_new_ekt(aad: bytes) -> bytes:
    """Create a new Encrypted Key Token.

    Creates a new Encrypted Key Token (EKT). The EKT is a wrapped Customer
    Master Key (CMK). A Customer Master Key is used to wrap customer secrets.
    The EKT returned by this function MUST be usable as an argument in the
    other functions of this interface, i.e. generate_new_secret,
    decrypt_secret, convert_secret.
    The EKT MUST be wrapped using AES256-GCM with the Additional Authenticated
    Data passed to this function. Be carreful to respect the best-practices
    for AES256-GCM, i.e. NEVER reuse an Initialization Vector. The best way to
    work-around is to wrap the CMK using a derivation from the parent KEK
    instead of the KEK itself.

    Args:
        aad: The Additional Authenticated Data used in the AES256-GCM
            algorithm.

    Returns:
        The newly generated Encrypted Key Token
    """

    logger.debug('HSM: Generating a new CMK')
    with open_token_session() as session:
        cmk_h = proteccio_generate_new_cmk(session)
        return proteccio_derive_kek_and_wrap(session,
            wrapping_key_handle=get_domain_key_handle(),
            secret_handle=cmk_h,
            aad=aad
        )

def generate_new_secret(secret_aad: bytes,
    ekt: bytes, ekt_aad: bytes,
    rsa_pub_key: bytes
    ) -> Tuple[bytes, bytes, bytes, bytes]:
    """Generate a new secret and wraps it both with a CMK and a RSA public key.

    Generate a new 256-bits Generic Secret using the PRNG of the token. The
    secret is extracted from the token wrapped in two ways. It is wrapped
    symetrically using AES256-GCM with the CMK of the customer (retrieved from
    the EKT). It is also wrapped using RSA-OAEP-SHA256 with the given RSA
    Public Key. Be carreful to respect the best-practices for AES256-GCM, i.e.
    NEVER reuse an Initialization Vector. The best way to work-around is to
    wrap the secret using a derivation from the CMK instead of the CMK itself.
    The AES256-GCM wrapped secret MUST be an acceptable argument for
    decrypt_secret and convert_secret.

    Args:
        secret_aad: The Additional Authenticated Data used in the AES256-GCM
            algorithm when wrapping the secret.
        ekt: The Encrypted Key Token of the CMK that will be used to wrap the
            secret.
        ekt_aad: The Additional Authenticated Data used in the AES256-GCM
            algorithm when un-wrapping the CMK from the EKT.
        rsa_pub_key: The DER encoded RSA Public Key to use to wrap the secret
            using RSA-OAEP-SHA256.

    Returns: A tuple (aes_wrapped_secret, aes_wrapped_secret_sig,
        rsa_wrapped_secret, rsa_wrapped_secret_sig), where aes_wrapped_secret
        is the AES256-GCM wrapped secret, aes_wrapped_secret_sig is the ECDSA
        signature blob of aes_wrapped_secret, rsa_wrapped_secret is the
        RSA-OAEP-SHA256 wrapped secret and rsa_wrapped_secret_sig is the ECDSA
        signature blob of rsa_wrapped_secret.
    """
    logger.debug('Generate and export a new secret')
    with open_token_session() as session:
        secret_h = proteccio_generate_new_secret(session)
        cmk_h = proteccio_derive_kek_and_unwrap(session,
            wrapping_key_handle=get_domain_key_handle(),
            cipher_text=ekt,
            aad=ekt_aad,
            target_key_type=KeyType.AES,
            extractable=False
        )
        rsa_h = proteccio_import_rsa_public_key(session, rsa_pub_key)
        aes_wrapped_secret = proteccio_derive_kek_and_wrap(session,
            wrapping_key_handle=cmk_h,
            secret_handle=secret_h,
            aad=secret_aad
        )
        aes_wrapped_secret_sig = sign(aes_wrapped_secret)
        rsa_wrapped_secret = proteccio_wrap_secret_rsa(session, rsa_h, secret_h)
        rsa_wrapped_secret_sig = sign(rsa_wrapped_secret)
    logger.debug('New secret retrieved from HSM both wrapped with the CMK and the RSA key')
    return aes_wrapped_secret, aes_wrapped_secret_sig, rsa_wrapped_secret, rsa_wrapped_secret_sig

def decrypt_secret(aes_wrapped_secret: bytes, secret_aad: bytes,
    ekt: bytes, ekt_aad: bytes,
    rsa_pub_key: bytes
    ) -> Tuple[bytes, bytes]:
    """Decrypt a secret and wraps it with a RSA public key.

    Unwrap the given secret using the CMK of the customer (retrieved from
    the EKT) then wraps it using RSA-OAEP-SHA256 with the given RSA Public Key.

    Args:
        aes_wrapped_secret: The AES256-GCM wrapped secret to unwrap.
        secret_aad: The Additional Authenticated Data used in the AES256-GCM
            algorithm when un-wrapping the secret.
        ekt: The Encrypted Key Token of the CMK that will be used to wrap the
            secret.
        ekt_aad: The Additional Authenticated Data used in the AES256-GCM
            algorithm when un-wrapping the CMK from the EKT.
        rsa_pub_key: The DER encoded RSA Public Key to use to wrap the secret
            using RSA-OAEP-SHA256.

    Returns: A tuple (rsa_wrapped_secret, rsa_wrapped_secret_sig), where
        rsa_wrapped_secret is the RSA-OAEP-SHA256 wrapped secret and
        rsa_wrapped_secret_sig is the ECDSA signature blob of
        rsa_wrapped_secret.
    """

    logger.debug('Decipher and export an existing secret')
    with open_token_session() as session:
        cmk_h = proteccio_derive_kek_and_unwrap(session,
            wrapping_key_handle=get_domain_key_handle(),
            cipher_text=ekt,
            aad=ekt_aad,
            target_key_type=KeyType.AES,
            extractable=False
        )
        rsa_h = proteccio_import_rsa_public_key(session, rsa_pub_key)
        secret_h = proteccio_derive_kek_and_unwrap(session,
            wrapping_key_handle=cmk_h,
            cipher_text=aes_wrapped_secret,
            aad=secret_aad,
            target_key_type=KeyType.GENERIC_SECRET,
            extractable=True
        )
        rsa_wrapped_secret = proteccio_wrap_secret_rsa(session, rsa_h, secret_h)
        rsa_wrapped_secret_sig = sign(rsa_wrapped_secret)
    logger.debug('Secret retrieved from HSM wrapped with the RSA key')
    return rsa_wrapped_secret, rsa_wrapped_secret_sig

def reencrypt_secret(aes_wrapped_secret: bytes,
    old_secret_aad: bytes, new_secret_aad: bytes,
    ekt: bytes, ekt_aad: bytes
    ) -> Tuple[bytes, bytes]:
    """Decrypt a secret and re-wraps it with another AAD.

    Unwrap the given secret using the CMK of the customer (retrieved from
    the EKT) and the current Additional Authenticated Data (AAD) and then
    re-wraps it using the same CMK but another AAD.

    Args:
        aes_wrapped_secret: The AES256-GCM wrapped secret to re-wrap.
        old_secret_aad: The Additional Authenticated Data used in the
            AES256-GCM algorithm when UN-wrapping the secret.
        new_secret_aad: The Additional Authenticated Data used in the
            AES256-GCM algorithm when RE-wrapping the secret.
        ekt: The Encrypted Key Token of the CMK that will be used to wrap the
            secret.
        ekt_aad: The Additional Authenticated Data used in the AES256-GCM
            algorithm when un-wrapping the CMK from the EKT.
        rsa_pub_key: The DER encoded RSA Public Key to use to wrap the secret
            using RSA-OAEP-SHA256.

    Returns: A tuple (new_aes_wrapped_secret, new_aes_wrapped_secret_sig),
        where new_aes_wrapped_secret is the AES256-GCM wrapped secret,
        new_aes_wrapped_secret_sig is the ECDSA signature blob of
        new_aes_wrapped_secret.
    """

    logger.debug('Decipher and re-encrypt an existing secret')
    with open_token_session() as session:
        cmk_h = proteccio_derive_kek_and_unwrap(session,
            wrapping_key_handle=get_domain_key_handle(),
            cipher_text=ekt,
            aad=ekt_aad,
            target_key_type=KeyType.AES,
            extractable=False
        )
        secret_h = proteccio_derive_kek_and_unwrap(session,
            wrapping_key_handle=cmk_h,
            cipher_text=aes_wrapped_secret,
            aad=secret_aad,
            target_key_type=KeyType.GENERIC_SECRET,
            extractable=True
        )
        new_aes_wrapped_secret = proteccio_derive_kek_and_wrap(session,
            wrapping_key_handle=cmk_h,
            secret_handle=secret_h,
            aad=new_secret_aad
        )
        new_aes_wrapped_secret_sig = sign(new_aes_wrapped_secret)
    logger.debug('Secret re-encrypted with the new context')
    return new_aes_wrapped_secret, new_aes_wrapped_secret_sig
