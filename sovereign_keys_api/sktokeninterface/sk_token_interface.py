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

from typing import Tuple

def is_token_ready() -> bool:
    """Verify the token is usable.

    Must return True only if the token (HSM) is reachable and ready to perform
    cryptographic duties, i.e. if the correct PIN is set.

    Returns:
        True if the token is reachable and ready to perform cryptographic
        duties, False otherwise.
    """

    raise NotImplementedError()

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

    raise NotImplementedError()

def export_public_signing_key() -> bytes:
    """Export the Public Signing Key.

    Export the Public part of the ECDSA KeyPair used to sign API responses and
    logs. It MUST be the Public Key part of the Key Pair used by the sign
    function.

    Returns:
        bytes: The DER encoded Public Key
    """

    raise NotImplementedError()

def sign(blob: bytes) -> bytes:
    """Sign a blob using ECDSA.

    Args:
        blob: Data to sign.

    Returns:
        sig: The DER-encoded ECDSA signature of the blob.
    """
    raise NotImplementedError()

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

    raise NotImplementedError()

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

    raise NotImplementedError()

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
    raise NotImplementedError()

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

    Returns: A tuple (aes_wrapped_secret, aes_wrapped_secret_sig), where
        aes_wrapped_secret is the AES256-GCM wrapped secret,
        aes_wrapped_secret_sig is the ECDSA signature blob of
        aes_wrapped_secret.
    """
    raise NotImplementedError()
