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

from utils import logger

from ctypes import CDLL
from ctypes import byref
from ctypes import c_ulong

from .constants import UserType, Error, Mechanism, ObjectType, Source, MGF, KeyType, PrfDataType
import skpkcs11.vendordefinedconstants.cloudhsm as cloudhsm_constants
import skpkcs11.vendordefinedconstants.proteccio as proteccio_constants
from .types import SessionFlag, Attribute
from .types import CK_RSA_PKCS_OAEP_PARAMS, CK_GCM_PARAMS, CK_KEY_DERIVATION_STRING_DATA
from .types import CK_SESSION_INFO, CK_ATTRIBUTE, CK_MECHANISM, CK_MECHANISM_INFO
from .types import CK_SP800_108_COUNTER_FORMAT, CK_SP800_108_DKM_LENGTH_FORMAT
from .types import CK_PRF_DATA_PARAM, CK_SP800_108_KDF_PARAMS
from .types import CK_C_INITIALIZE_ARGS

from .utils import get_void_pointer_and_len, get_value_from_void_pointer_and_len, get_buffer

from threading import Lock

from enum import Enum, auto

class HSMFamily(Enum):
    PROTECCIO = auto()
    CLOUDHSM = auto()

class PKCS11Lib:
    __known_lib = {}
    __factory_lock = Lock()

    def __init__(self, pkcs11_lib_path, hsm_family):
        # Load Proteccio PKCS11 lib
        self.__lib = CDLL(pkcs11_lib_path)
        self.__hsm_family = hsm_family
        self.__init_lock = Lock()
        self.__init_count = 0
        self.__initialized = False
        self.__remote_op_lock = Lock()

    def __initialize(self):
        logger.debug('Entering PKCS11Lib.__initialize')
        # Initialize
        self.__initialized = True
        args = CK_C_INITIALIZE_ARGS(0,0,0,0,2,0)
        RV = self.__lib.C_Initialize(byref(args))
        if RV == Error.CRYPTOKI_ALREADY_INITIALIZED:
            logger.warning('C_Initialize failed with error CRYPTOKI_ALREADY_INITIALIZED')
        elif RV != 0:
            self.__lib.C_Finalize(None)
            raise Exception(f'C_Initialize failed with error {Error(RV).name}')
        logger.debug('Exiting PKCS11Lib.__initialize')

    def __finalize(self):
        logger.debug('Entering PKCS11Lib.__finalize')
        # Finalize
        RV = self.__lib.C_Finalize(None)
        if RV != 0:
            raise Exception(f'C_Finalize failed with error {Error(RV).name}')
        logger.debug('Exiting PKCS11Lib.__finalize')

    def _enter(self):
        with self.__init_lock:
            if self.__init_count == 0:
                self.__initialize()
            self.__init_count += 1

    def __enter__(self):
        self._enter()
        return self

    def _exit(self):
        with self.__init_lock:
            self.__init_count -= 1
            if self.__init_count <= 0:
                self.__finalize()

    def __exit__(self, type_, value, traceback):
        self._exit()

    @property
    def remote_op_lock(self):
        return self.__remote_op_lock

    @property
    def lib(self):
        return self.__lib

    @property
    def hsm_family(self):
        return self.__hsm_family

    @property
    def _initialized(self):
        return self.__initialized

    @classmethod
    def get_instance(cls, pkcs11_lib_path, hsm_family):
        if pkcs11_lib_path not in cls.__known_lib:
            with cls.__factory_lock:
                if pkcs11_lib_path not in cls.__known_lib:
                    cls.__known_lib[pkcs11_lib_path] = cls(pkcs11_lib_path, hsm_family)
        return cls.__known_lib[pkcs11_lib_path]

    def get_token(self, slot):
        return Token(pkcs11lib=self, slot=slot)

    def get_slot_list(self, tokenPresent=True):
        with self:
            # Number of slot
            count = c_ulong()
            # Make the call to retrieve the number of slot
            with self.__remote_op_lock:
                RV = self.__lib.C_GetSlotList(tokenPresent, None, byref(count))
            if RV != 0:
                raise Exception(f'C_GetSlotList failed with error {Error(RV).name}')

            logger.info(f"Slot Count={count.value}")
            # Slot list buffer
            slot_list = (c_ulong * count.value)()
            # Make the call
            with self.__remote_op_lock:
                RV = self.__lib.C_GetSlotList(tokenPresent, byref(slot_list), byref(count))
            if RV != 0:
                raise Exception(f'C_GetSlotList failed with error {Error(RV).name}')
            # Return list with values
            return slot_list[:count.value]

class ProteccioLib(PKCS11Lib):
    @classmethod
    def get_instance(cls, pkcs11_lib_path):
        return super().get_instance(pkcs11_lib_path, HSMFamily.PROTECCIO)

class CloudHSMLib(PKCS11Lib):
    @classmethod
    def get_instance(cls, pkcs11_lib_path):
        return super().get_instance(pkcs11_lib_path, HSMFamily.CLOUDHSM)

class Token:
    def __init__(self, pkcs11lib, slot=None):
        self.__pkcs11lib = pkcs11lib
        self.__lib = pkcs11lib.lib
        if slot is None:
            slot_list = pkcs11lib.get_slot_list()
            logger.debug(f"Tokens available on slots: {slot_list}. Using the SLOT {slot_list[0]}")
            slot = slot_list[0]
        self.__slot = slot
        self.__opened_session = None
        self.__session_lock = Lock()

    @property
    def pkcs11lib(self):
        return self.__pkcs11lib

    @property
    def remote_op_lock(self):
        return self.__pkcs11lib.remote_op_lock

    @property
    def slot(self):
        return self.__slot

    def session(self, pin=None):
        with self.__session_lock:
            if self.__opened_session is None or self.__opened_session.is_session_terminated():
                self.__opened_session = Session(token=self, pin=pin)
            return self.__opened_session

    def get_mechanism_info(self, mecanism):
        with self.__pkcs11lib:
            assert isinstance(mecanism, Mechanism)
            # Slot ID
            slot_id = self.__slot

            # Init a CK_MECHANISM_INFO structure filled with 0s
            mechanism_info = CK_MECHANISM_INFO(0, 0, 0)

            # Make the call
            with self.__remote_op_lock:
                RV = self.__lib.C_GetMechanismInfo(c_ulong(slot_id), mecanism, byref(mechanism_info))
            if RV != 0:
                raise Exception(f'C_GetMechanismInfo failed with error {Error(RV).name}')

            # Return dict with values
            return {
                'MinKeySize': mechanism_info.ulMinKeySize,
                'MaxKeySize': mechanism_info.ulMaxKeySize,
                'Flags': [f.name for f in mechanism_info.get_flags()],
            }

class BadPINException(Exception):
    pass

class Session:
    def __init__(self, token, pin):
        self.__token = token
        self.__pkcs11lib = token.pkcs11lib
        self.__lib = token.pkcs11lib.lib
        self.__hsm_family = token.pkcs11lib.hsm_family
        self.__open_lock = Lock()
        self.__remote_op_lock = self.__token.remote_op_lock
        self.__open_count = 0
        self.__pin = pin
        self.__session_opened = False
        self.__logged_in = False

    def _open(self):
        logger.debug('Entering Session._open')
        # Initialize an empty cache
        self._obj_handle_cache = {}

        """Will open a session and then login using the PIN argument"""
        # Open the session
        slotID = self.__token.slot
        flags = SessionFlag.RW_SESSION | SessionFlag.SERIAL_SESSION
        hSession = c_ulong()
        self.__session_opened = True
        RV = self.__lib.C_OpenSession(c_ulong(slotID), flags, None, None, byref(hSession))
        if RV != 0:
            raise Exception(f'C_OpenSession failed with error {Error(RV).name}')
        if hSession.value <= 0:
            raise Exception(f'C_OpenSession returned a bad handle: {hSession.value}')
        self.__handle = hSession

        logger.debug('Exiting Session._open')

    def _login(self):
        logger.debug('Entering Session._login')
        user_type = UserType.USER
        ppin, spin = get_void_pointer_and_len(self.__pin)
        self.__logged_in = True
        RV = self.__lib.C_Login(self.__handle, user_type, ppin, spin)
        if RV == Error.PIN_INCORRECT or RV == Error.PIN_INVALID:
            raise BadPINException(f'C_Login failed with error {Error(RV).name}')
        if RV != 0:
            raise Exception(f'C_Login failed with error {Error(RV).name}')
        logger.debug('Exiting Session._login')

    def _logout(self):
        logger.debug('Entering Session._logout')
        if self.__logged_in:
            RV = self.__lib.C_Logout(self.__handle)
            if RV != 0:
                raise Exception(f'C_Logout failed with error {Error(RV).name}')
        logger.debug('Exiting Session._logout')

    def _close(self):
        logger.debug('Entering Session._close')
        if self.__session_opened:
            RV = self.__lib.C_CloseSession(self.__handle)
            if RV != 0:
                raise Exception(f'C_CloseSession failed with error {Error(RV).name}')
        logger.debug('Exiting Session._close')

    def __enter__(self):
        with self.__open_lock:
            if self.__open_count == 0:
                self.__pkcs11lib._enter()
                self._open()
                if self.__pin is not None:
                    self._login()
            self.__open_count += 1
        return self

    def __exit__(self, type_, value, traceback):
        with self.__open_lock:
            self.__open_count -= 1
            if self.__open_count <= 0:
                if self.__logged_in:
                    self._logout()
                if self.__session_opened:
                    self._close()
                if self.__pkcs11lib._initialized:
                    self.__pkcs11lib._exit()

    def is_session_terminated(self):
        with self.__open_lock:
            return self.__open_count <= 0 and self.__session_opened

    def get_session_info(self):
        # Session handle
        hSession = self.__handle

        # Init a CK_SESSION_INFO structure filled with 0s
        session_info = CK_SESSION_INFO(0, 0, 0, 0)

        # Make the call
        with self.__remote_op_lock:
            RV = self.__lib.C_GetSessionInfo(hSession, byref(session_info))
        if RV != 0:
            raise Exception(f'C_GetSessionInfo failed with error {Error(RV).name}')

        # Return dict with values
        return {
            'slotID': session_info.slotID,
            'state': session_info.get_state().name,
            'flags': [f.name for f in session_info.get_flags()],
            'ulDeviceError': session_info.ulDeviceError,
        }

    def generate_random(self, size):
        """Use the token to generate random bytes of `size` bytes"""
        # Create a buffer of len `size`
        hSession = self.__handle
        buf, buf_len = get_buffer(size)
        with self.__remote_op_lock:
            RV = self.__lib.C_GenerateRandom(hSession, buf, buf_len)
        if RV != 0:
            raise Exception(f'C_GenerateRandom failed with error {Error(RV).name}')
        buf = buf[:size]
        if len(buf) != size:
            raise Exception('The random data size returned by the token did not match the requested size')
        return buf

    def get_object_handle(self, label=None):
        if label in self._obj_handle_cache:
            return self._obj_handle_cache[label]
        """Try to find an object with LABEL attribute `label`"""
        # Create a template
        attrs = list()
        if label is not None:
            attrs.append(CK_ATTRIBUTE.construct(Attribute.LABEL, label))
        template = CK_ATTRIBUTE.get_array_of(attrs)

        with self.__remote_op_lock:
            # Initialize a search
            search_it = SearchIter(lib=self.__lib, hSession=self.__handle, template=template)
            try:
                objHandle = next(search_it)
            except StopIteration:
                return 0
            # If there is more than one match we will consider it abnormal
            try:
                # Should throw a StopIteration exception
                next(search_it)
                # If we are past this point, it means there is more than 1 match
                search_it.close()
                raise Exception(f'More than 1 object matches label {label}')
            except StopIteration:
                # That's the expected behavior in our case
                self._obj_handle_cache[label] = objHandle
                return objHandle

    def create_secret_key(self,
            key_label,
            key_gen_mech=Mechanism.AES_KEY_GEN,
            key_size_in_bits=256,
            token=False,
            sensitive=False,
            private=False,
            modifiable=False,
            extractable=False,
            sign=False,
            verify=False,
            encrypt=False,
            decrypt=False,
            wrap=False,
            unwrap=False,
            derive=False
        ):
        """Create a new secret key"""
        # Session handle
        hSession = self.__handle
        # Mechanism
        pMechanism = byref(CK_MECHANISM.construct(key_gen_mech))
        # Template
        attrs = [
            CK_ATTRIBUTE.construct(Attribute.LABEL, key_label),
            # CK_ATTRIBUTE.construct(Attribute.ID),
            CK_ATTRIBUTE.construct(Attribute.CLASS, ObjectType.SECRET_KEY),
            CK_ATTRIBUTE.construct(Attribute.TOKEN, token),
            CK_ATTRIBUTE.construct(Attribute.SENSITIVE, sensitive),
            CK_ATTRIBUTE.construct(Attribute.PRIVATE, private),
            CK_ATTRIBUTE.construct(Attribute.ENCRYPT, encrypt),
            CK_ATTRIBUTE.construct(Attribute.DECRYPT, decrypt),
            CK_ATTRIBUTE.construct(Attribute.SIGN, sign),
            CK_ATTRIBUTE.construct(Attribute.VERIFY, verify),
            CK_ATTRIBUTE.construct(Attribute.WRAP, wrap),
            CK_ATTRIBUTE.construct(Attribute.UNWRAP, unwrap),
            CK_ATTRIBUTE.construct(Attribute.DERIVE, derive),
            CK_ATTRIBUTE.construct(Attribute.MODIFIABLE, modifiable),
            CK_ATTRIBUTE.construct(Attribute.EXTRACTABLE, extractable),
            CK_ATTRIBUTE.construct(Attribute.VALUE_LEN, key_size_in_bits//8)
        ]
        template = CK_ATTRIBUTE.get_array_of(attrs)
        # Future key handle
        h = c_ulong()

        with self.__remote_op_lock:
            RV = self.__lib.C_GenerateKey(hSession, pMechanism, byref(template), len(template), byref(h))
        if RV != 0:
            raise Exception(f'C_GenerateKey failed with error {Error(RV).name}')
        if h.value <= 0:
            raise Exception(f'C_GenerateKey returned a bad handle: {h.value}')
        return h.value

    def derive_master_key(self,
            base_key_handle,
            derive_key_mech,
            nonce,
            key_label,
            key_type,
            key_size_in_bits=256,
            token=False,
            sensitive=False,
            private=False,
            modifiable=False,
            extractable=False,
            sign=False,
            verify=False,
            encrypt=False,
            decrypt=False,
            wrap=False,
            unwrap=False,
            derive=False
        ):
        """Derive a new secret key """
        # Session handle
        hSession = self.__handle
        if derive_key_mech == Mechanism.AES_ECB_ENCRYPT_DATA:
            # Not supported by CloudHSM
            if self.__hsm_family == HSMFamily.CLOUDHSM:
                raise Exception(f'Mechanism {derive_key_mech} is not supported')
            # Mechanism
            pNonce, nonce_len = get_void_pointer_and_len(nonce)
            mech_param = CK_KEY_DERIVATION_STRING_DATA(
                pNonce,
                nonce_len
            )
            # Mechanism
            pMechanism = byref(CK_MECHANISM.construct(derive_key_mech, mech_param))
        elif derive_key_mech == (
            Mechanism.VENDOR_DEFINED
            | cloudhsm_constants.Mechanism.SP800_108_COUNTER_KDF
            ):
            # Supported only by CloudHSM
            if self.__hsm_family != HSMFamily.CLOUDHSM:
                raise Exception(f'Mechanism {derive_key_mech} is not supported')
            # Mechanism
            counter_format = CK_SP800_108_COUNTER_FORMAT(32) # 16 or 32
            dkm_format = CK_SP800_108_DKM_LENGTH_FORMAT(1, 32)
            kdf_data_params = [
                CK_PRF_DATA_PARAM.construct(PrfDataType.SP800_108_COUNTER_FORMAT, counter_format),
                CK_PRF_DATA_PARAM.construct(PrfDataType.SP800_108_DKM_FORMAT, dkm_format),
                CK_PRF_DATA_PARAM.construct(PrfDataType.SP800_108_PRF_LABEL, "sk"),
                CK_PRF_DATA_PARAM.construct(PrfDataType.SP800_108_PRF_CONTEXT, nonce)
            ]
            kdf_data_params = CK_PRF_DATA_PARAM.get_array_of(kdf_data_params)

            mech_param = CK_SP800_108_KDF_PARAMS(
                Mechanism.SHA256_HMAC,
                len(kdf_data_params),
                get_void_pointer_and_len(kdf_data_params)[0] # We use only the first elem of the tuple, i.e. the pointer (thus discarding the size)
            )
            # Mechanism
            pMechanism = byref(CK_MECHANISM.construct(derive_key_mech, mech_param))
        else:
            raise Exception(f'Mechanism {derive_key_mech} is not supported')

        # Template
        attrs = [
            CK_ATTRIBUTE.construct(Attribute.LABEL, key_label),
            # CK_ATTRIBUTE.construct(Attribute.ID),
            CK_ATTRIBUTE.construct(Attribute.CLASS, ObjectType.SECRET_KEY),
            CK_ATTRIBUTE.construct(Attribute.KEY_TYPE, key_type),
            CK_ATTRIBUTE.construct(Attribute.TOKEN, token),
            CK_ATTRIBUTE.construct(Attribute.SENSITIVE, sensitive),
            CK_ATTRIBUTE.construct(Attribute.PRIVATE, private),
            CK_ATTRIBUTE.construct(Attribute.ENCRYPT, encrypt),
            CK_ATTRIBUTE.construct(Attribute.DECRYPT, decrypt),
            CK_ATTRIBUTE.construct(Attribute.SIGN, sign),
            CK_ATTRIBUTE.construct(Attribute.VERIFY, verify),
            CK_ATTRIBUTE.construct(Attribute.WRAP, wrap),
            CK_ATTRIBUTE.construct(Attribute.UNWRAP, unwrap),
            CK_ATTRIBUTE.construct(Attribute.DERIVE, derive),
            CK_ATTRIBUTE.construct(Attribute.MODIFIABLE, modifiable),
            CK_ATTRIBUTE.construct(Attribute.EXTRACTABLE, extractable),
            CK_ATTRIBUTE.construct(Attribute.VALUE_LEN, key_size_in_bits//8)
        ]
        template = CK_ATTRIBUTE.get_array_of(attrs)
        # Future key handle
        h = c_ulong()

        with self.__remote_op_lock:
            RV = self.__lib.C_DeriveKey(hSession, pMechanism, c_ulong(base_key_handle), byref(template), len(template), byref(h))
        if RV != 0:
            raise Exception(f'C_DeriveKey failed with error {Error(RV).name}')
        if h.value <= 0:
            raise Exception(f'C_DeriveKey returned a bad handle: {h.value}')
        return h.value

    def wrap_key_asym(self,
            key_handle,
            wrap_key_handle,
            wrap_key_mech
        ):
        """Wrap a key with another key"""
        # Session handle
        hSession = self.__handle
        if wrap_key_mech == Mechanism.RSA_PKCS_OAEP:
            # piv, iv_len = get_void_pointer_and_len(wrap_key_iv)
            mech_param = CK_RSA_PKCS_OAEP_PARAMS(
                Mechanism.SHA256,
                MGF.MGF1_SHA256,
                Source.DATA_SPECIFIED,
                # piv,      # Impossible to understand how to decrypt the
                # iv_len    # wrapped value with openssl if we use that
                None,
                0
            )
            # Mechanism
            pMechanism = byref(CK_MECHANISM.construct(wrap_key_mech, mech_param))
        else:
            raise Exception(f'Mechanism {wrap_key_mech} is not supported')
        # Buffer
        buf, buf_len = get_buffer()

        with self.__remote_op_lock:
            RV = self.__lib.C_WrapKey(hSession, pMechanism, c_ulong(wrap_key_handle), c_ulong(key_handle), buf, byref(buf_len))
        if RV != 0:
            raise Exception(f'C_WrapKey failed with error {Error(RV).name}')

        # Result size
        wrap_size = buf_len.value
        return buf[:wrap_size]

    def wrap_key_sym(self,
            key_handle,
            wrap_key_handle,
            wrap_key_mech,
            wrap_key_iv=None,
            aad=None
        ):
        """Wrap a key with another key"""
        # Session handle
        hSession = self.__handle
        if wrap_key_mech == Mechanism.AES_CBC_PAD:
            if self.__hsm_family == HSMFamily.CLOUDHSM:
                raise Exception(f'Mechanism {wrap_key_mech} is not supported')
            # Mechanism
            pMechanism = byref(CK_MECHANISM.construct(wrap_key_mech, wrap_key_iv))
        elif wrap_key_mech == Mechanism.AES_GCM:
            if self.__hsm_family == HSMFamily.CLOUDHSM:
                # CloudHSM will handle the IV generation on its side
                piv, iv_len = get_void_pointer_and_len(bytes(12))  # Creates a 96-bits buffer
            else:
                # Else we ensure we have an IV or generates it
                if wrap_key_iv is None:
                    wrap_key_iv = generate_random(12) # Generate a 96-bits random value
                piv, iv_len = get_void_pointer_and_len(wrap_key_iv)

            paad, aad_len = get_void_pointer_and_len(aad)
            mech_param = CK_GCM_PARAMS(
                piv,
                iv_len,
                iv_len * 8, # Apparently we have to help the token compute the equivalence between bytes and bit
                paad,
                aad_len,
                128 # Tag len
            )
            # Mechanism
            pMechanism = byref(CK_MECHANISM.construct(wrap_key_mech, mech_param))
        else:
            raise Exception(f'Mechanism {wrap_key_mech} is not supported')
        # Buffer
        buf, buf_len = get_buffer()

        with self.__remote_op_lock:
            RV = self.__lib.C_WrapKey(hSession, pMechanism, c_ulong(wrap_key_handle), c_ulong(key_handle), buf, byref(buf_len))
        if RV != 0:
            raise Exception(f'C_WrapKey failed with error {Error(RV).name}')

        # Result size
        wrap_size = buf_len.value
        # We return the IV and the result
        return get_value_from_void_pointer_and_len(bytes, piv, iv_len), buf[:wrap_size]

    def unwrap_key_sym(self,
            key_data,
            wrap_key_handle,
            wrap_key_mech,
            wrap_key_iv,
            key_label,
            key_type,
            key_size_in_bits=256,
            aad=None,
            token=False,
            private=False,
            sensitive=False,
            modifiable=False,
            extractable=False,
            sign=False,
            verify=False,
            encrypt=False,
            decrypt=False,
            wrap=False,
            unwrap=False,
            derive=False
        ):
        """Unwrap a secret key"""
        # Session handle
        hSession = self.__handle
        # By default, we ignore the key_size
        ignore_key_size = True
        # Mechanism
        if wrap_key_mech == Mechanism.AES_CBC_PAD:
            if self.__hsm_family == HSMFamily.CLOUDHSM:
                raise Exception(f'Mechanism {wrap_key_mech} is not supported')
            # Mechanism
            pMechanism = byref(CK_MECHANISM.construct(wrap_key_mech, wrap_key_iv))
        elif wrap_key_mech == Mechanism.AES_GCM:
            piv, iv_len = get_void_pointer_and_len(wrap_key_iv)
            paad, aad_len = get_void_pointer_and_len(aad)
            mech_param = CK_GCM_PARAMS(
                piv,
                iv_len,
                iv_len * 8, # Apparently we have to help the token compute the equivalence between bytes and bit
                paad,
                aad_len,
                128 # Tag len
            )
            # Mechanism
            pMechanism = byref(CK_MECHANISM.construct(wrap_key_mech, mech_param))
        else:
            raise Exception(f'Mechanism {wrap_key_mech} is not supported')
        # Pointer and size on data
        pwk, pwk_len = get_void_pointer_and_len(key_data)
        # Template
        attrs = [
            CK_ATTRIBUTE.construct(Attribute.LABEL, key_label),
            # CK_ATTRIBUTE.construct(Attribute.ID),
            CK_ATTRIBUTE.construct(Attribute.CLASS, ObjectType.SECRET_KEY),
            CK_ATTRIBUTE.construct(Attribute.KEY_TYPE, key_type),
            CK_ATTRIBUTE.construct(Attribute.TOKEN, token),
            CK_ATTRIBUTE.construct(Attribute.SENSITIVE, sensitive),
            CK_ATTRIBUTE.construct(Attribute.PRIVATE, private),
            CK_ATTRIBUTE.construct(Attribute.ENCRYPT, encrypt),
            CK_ATTRIBUTE.construct(Attribute.DECRYPT, decrypt),
            CK_ATTRIBUTE.construct(Attribute.SIGN, sign),
            CK_ATTRIBUTE.construct(Attribute.VERIFY, verify),
            CK_ATTRIBUTE.construct(Attribute.WRAP, wrap),
            CK_ATTRIBUTE.construct(Attribute.UNWRAP, unwrap),
            CK_ATTRIBUTE.construct(Attribute.DERIVE, derive),
            CK_ATTRIBUTE.construct(Attribute.MODIFIABLE, modifiable),
            CK_ATTRIBUTE.construct(Attribute.EXTRACTABLE, extractable)
        ]
        if not ignore_key_size:
            attrs.append(CK_ATTRIBUTE.construct(Attribute.VALUE_LEN, key_size_in_bits//8))
        template = CK_ATTRIBUTE.get_array_of(attrs)
        # Future key handle
        h = c_ulong()

        with self.__remote_op_lock:
            RV = self.__lib.C_UnwrapKey(hSession, pMechanism, c_ulong(wrap_key_handle), pwk, pwk_len, byref(template), len(template), byref(h))
        if RV != 0:
            raise Exception(f'C_UnwrapKey failed with error {Error(RV).name}')
        if h.value <= 0:
            raise Exception(f'C_UnwrapKey returned a bad handle: {h.value}')
        return h.value

    def import_rsa_public_key(self,
            key_label,
            modulus,
            exponent,
            token=False,
            private=False,
            modifiable=False,
            verify=False,
            encrypt=False,
            wrap=False
        ):
        """Import a public RSA key into the token"""
        # Session handle
        hSession = self.__handle
        # Template
        attrs = [
            CK_ATTRIBUTE.construct(Attribute.LABEL, key_label),
            # CK_ATTRIBUTE.construct(Attribute.ID),
            CK_ATTRIBUTE.construct(Attribute.CLASS, ObjectType.PUBLIC_KEY),
            CK_ATTRIBUTE.construct(Attribute.KEY_TYPE, KeyType.RSA),
            CK_ATTRIBUTE.construct(Attribute.MODULUS, modulus),
            CK_ATTRIBUTE.construct(Attribute.PUBLIC_EXPONENT, exponent),
            CK_ATTRIBUTE.construct(Attribute.TOKEN, token),
            CK_ATTRIBUTE.construct(Attribute.PRIVATE, private),
            CK_ATTRIBUTE.construct(Attribute.ENCRYPT, encrypt),
            CK_ATTRIBUTE.construct(Attribute.VERIFY, verify),
            CK_ATTRIBUTE.construct(Attribute.WRAP, wrap),
            CK_ATTRIBUTE.construct(Attribute.MODIFIABLE, modifiable)
        ]
        template = CK_ATTRIBUTE.get_array_of(attrs)
        # Future key handle
        h = c_ulong()

        with self.__remote_op_lock:
            RV = self.__lib.C_CreateObject(hSession, byref(template), len(template), byref(h))
        if RV != 0:
            raise Exception(f'C_CreateObject failed with error {Error(RV).name}')
        if h.value <= 0:
            raise Exception(f'C_CreateObject returned a bad handle: {h.value}')
        return h.value

    def create_ec_key_pair(self,
            private_key_label,
            public_key_label,
            token=False,
            private=True,
            modifiable=True,
            extractable=True,
            sensitive=True
        ):
        """Create a new EC keypair"""
        # Session handle
        hSession = self.__handle
        # Mechanism
        pMechanism = byref(CK_MECHANISM.construct(Mechanism.EC_KEY_PAIR_GEN))
        # Template pub
        attrs_pub = [
            CK_ATTRIBUTE.construct(Attribute.LABEL, public_key_label),
            # Would be "nice to have" to support the FRP256v1 curve from ANSSI but it will require additionnal work
            # ANSSI also accept, among other curves, the secp384r1 curve.
            # Below is the DER encoding of OID 1.3.132.0.34 which is the one of the secp384r1 curve.
            CK_ATTRIBUTE.construct(Attribute.EC_PARAMS, b'\x06\x05+\x81\x04\x00"'),
            # CK_ATTRIBUTE.construct(Attribute.ID),
            CK_ATTRIBUTE.construct(Attribute.TOKEN, token),
            CK_ATTRIBUTE.construct(Attribute.PRIVATE, private),
            CK_ATTRIBUTE.construct(Attribute.MODIFIABLE, modifiable),
            CK_ATTRIBUTE.construct(Attribute.VERIFY, True),
            CK_ATTRIBUTE.construct(Attribute.ENCRYPT, False),
            CK_ATTRIBUTE.construct(Attribute.WRAP, False),
            CK_ATTRIBUTE.construct(Attribute.DERIVE, False)
        ]
        template_pub = CK_ATTRIBUTE.get_array_of(attrs_pub)
        # Template priv
        attrs_priv = [
            CK_ATTRIBUTE.construct(Attribute.LABEL, private_key_label),
            # CK_ATTRIBUTE.construct(Attribute.ID),
            CK_ATTRIBUTE.construct(Attribute.TOKEN, token),
            CK_ATTRIBUTE.construct(Attribute.SENSITIVE, sensitive),
            CK_ATTRIBUTE.construct(Attribute.PRIVATE, private),
            CK_ATTRIBUTE.construct(Attribute.MODIFIABLE, modifiable),
            CK_ATTRIBUTE.construct(Attribute.EXTRACTABLE, extractable),
            CK_ATTRIBUTE.construct(Attribute.SIGN, True),
            CK_ATTRIBUTE.construct(Attribute.DECRYPT, False),
            CK_ATTRIBUTE.construct(Attribute.UNWRAP, False),
            CK_ATTRIBUTE.construct(Attribute.DERIVE, False)
        ]
        template_priv = CK_ATTRIBUTE.get_array_of(attrs_priv)
        # Future key handles
        h_pub = c_ulong()
        h_priv = c_ulong()

        with self.__remote_op_lock:
            RV = self.__lib.C_GenerateKeyPair(hSession, pMechanism, byref(template_pub), len(template_pub), byref(template_priv), len(template_priv), byref(h_pub), byref(h_priv))
        if RV != 0:
            raise Exception(f'C_GenerateKeyPair failed with error {Error(RV).name}')
        if h_pub.value <= 0 or h_priv.value <= 0:
            raise Exception(f'C_GenerateKeyPair returned a bad handle: ({h_pub.value},{h_priv.value})')
        return h_pub.value, h_priv.value

    def sign(self,
        key_handle,
        signing_mech,
        data
        ):
        # Session handle
        hSession = self.__handle

        # Mechanism
        pMechanism = byref(CK_MECHANISM.construct(signing_mech))

        # Get pointer
        pdata, data_len = get_void_pointer_and_len(data)

        # Buffer
        buf, buf_len = get_buffer()

        # Sign
        with self.__remote_op_lock:
            # Init signature
            RV = self.__lib.C_SignInit(hSession, pMechanism, c_ulong(key_handle))
            if RV != 0:
                raise Exception(f'C_SignInit failed with error {Error(RV).name}')
            # Sign
            RV = self.__lib.C_Sign(hSession, pdata, data_len, buf, byref(buf_len))
            if RV != 0:
                raise Exception(f'C_Sign failed with error {Error(RV).name}')

        # Result size
        sig_size = buf_len.value
        return buf[:sig_size]

    def get_attributes(self,
        object_handle,
        attr_list
        ):
        # Session handle
        hSession = self.__handle

        # Template
        attrs = [
            CK_ATTRIBUTE.construct(Attribute[a.upper()], get_buffer()[0])
            for a in attr_list
        ]
        template = CK_ATTRIBUTE.get_array_of(attrs)

        with self.__remote_op_lock:
            RV = self.__lib.C_GetAttributeValue(hSession, c_ulong(object_handle), byref(template), len(template))
        if RV != 0:
            raise Exception(f'C_GetAttributeValue failed with error {Error(RV).name}')

        # Convert the template back to a dict of key:val with the attributes name passed to the method
        template_index = {
            Attribute(attr_struct.type).name:attr_struct.get_value()
            for attr_struct in template
        }

        return {
            a:template_index[a.upper()]
            for a in attr_list
        }

    def destroy_object(self,
        object_handle
        ):
        # Session handle
        hSession = self.__handle

        with self.__remote_op_lock:
            RV = self.__lib.C_DestroyObject(hSession, c_ulong(object_handle))
        if RV != 0:
            raise Exception(f'C_DestroyObject failed with error {Error(RV).name}')

        return True

class SearchIter:
    """Iterate a search for objects on a session."""

    def __init__(self, lib, hSession, template):
        self.__active = True
        self.__lib = lib
        self.__handle = hSession

        RV = self.__lib.C_FindObjectsInit(hSession, byref(template), len(template))
        if RV != 0:
            raise Exception(f'C_FindObjectsInit failed with error {Error(RV).name}')

    def __iter__(self):
        return self

    def __next__(self):
        """Get the next object."""
        h = c_ulong()
        count = c_ulong()
        RV = self.__lib.C_FindObjects(self.__handle, byref(h), 1, byref(count))
        if RV != 0:
            raise Exception(f'C_FindObjects failed with error {Error(RV).name}')

        if count.value == 0:
            self._finalize()
            raise StopIteration()
        else:
            return h.value

    def __del__(self):
        """Close the search."""
        self._finalize()

    def close(self):
        """Close the search."""
        self._finalize()

    def _finalize(self):
        """Finish the operation."""
        if self.__active:
            self.__active = False
            RV = self.__lib.C_FindObjectsFinal(self.__handle)
            if RV != 0:
                raise Exception(f'C_FindObjectsFinal failed with error {Error(RV).name}')

# Don't use this
# TODO: Correctly implement locking mechanism
class SignObject:
    """Allow to perform a signature"""

    def __init__(self, lib, hSession, key_handle, signing_mech):
        self.__active = True
        self.__lib = lib
        self.__handle = hSession

        # Mechanism
        pMechanism = byref(CK_MECHANISM.construct(signing_mech))
        RV = self.__lib.C_SignInit(self.__handle, pMechanism, c_ulong(key_handle))
        if RV != 0:
            raise Exception(f'C_SignInit failed with error {Error(RV).name}')

    def __del__(self):
        """Close the sign operation."""
        if self.__active:
            self.signature()

    def update(self, data):
        pPart, part_len = get_void_pointer_and_len(data)
        RV = self.__lib.C_SignUpdate(self.__handle, pPart, part_len)
        if RV != 0:
            raise Exception(f'C_SignUpdate failed with error {Error(RV).name}')

    def signature(self):
        # Buffer
        buf, buf_len = get_buffer()

        RV = self.__lib.C_SignFinal(self.__handle, buf, byref(buf_len))
        if RV != 0:
            raise Exception(f'C_SignFinal failed with error {Error(RV).name}')
        self.__active = False
        # Result size
        sig_size = buf_len.value
        return buf[:sig_size]
