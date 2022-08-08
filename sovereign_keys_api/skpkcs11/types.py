# Not everything is declared is this file
# Only what was needed or what we though we needed at some point
from ctypes import Structure
from ctypes import c_void_p
from ctypes import c_char_p
from ctypes import c_ulong
from ctypes import c_uint
from ctypes import c_bool
from ctypes import c_byte

from ctypes import cast
from ctypes import sizeof
from ctypes import pointer

from .constants import Mechanism
from .constants import MechanismFlag
from .constants import Attribute
from .constants import PrfDataType
from .constants import SessionState
from .constants import SessionFlag

from .utils import get_void_pointer_and_len
from .utils import get_value_from_void_pointer_and_len

class CK_ATTRIBUTE(Structure):
    _fields_ = [
        ("type", c_ulong),
        ("pValue", c_void_p),
        ("ulValueLen", c_ulong)
    ]

    @classmethod
    def construct(cls, atype, value=None):
        assert isinstance(atype, Attribute)
        p, s = get_void_pointer_and_len(value)
        return cls(
            atype,
            p,
            s
        )

    @classmethod
    def get_array_of(cls, l):
        count = len(l)
        array = cls * count
        return array(*l)

    def get_value(self):
        attr_type = Attribute(self.type).get_type()
        return get_value_from_void_pointer_and_len(attr_type, self.pValue, self.ulValueLen)

# typedef struct CK_MECHANISM {
#   CK_MECHANISM_TYPE mechanism;
#   CK_VOID_PTR       pParameter;
#   /* ulParameterLen was changed from CK_USHORT to CK_ULONG for
#    * v2.0 */
#   CK_ULONG          ulParameterLen;  /* in bytes */
# } CK_MECHANISM;
class CK_MECHANISM(Structure):
    _fields_ = [
        ("mechanism", c_ulong),
        ("pParameter", c_void_p),
        ("ulParameterLen", c_ulong)
    ]
    @classmethod
    def construct(cls, mech, value=None):
        p, s = get_void_pointer_and_len(value)
        return cls(
            mech,
            p,
            s
        )


# typedef struct CK_GCM_PARAMS {
#     CK_BYTE_PTR       pIv;
#     CK_ULONG          ulIvLen;
#     CK_ULONG          ulIvBits;
#     CK_BYTE_PTR       pAAD;
#     CK_ULONG          ulAADLen;
#     CK_ULONG          ulTagBits;
# } CK_GCM_PARAMS;
# typedef CK_GCM_PARAMS CK_PTR CK_GCM_PARAMS_PTR;
class CK_GCM_PARAMS(Structure):
    _fields_ = [
        ("pIv", c_void_p),
        ("ulIvLen", c_ulong),
        ("ulIvBits", c_ulong),
        ("pAAD", c_void_p),
        ("ulAADLen", c_ulong),
        ("ulTagBits", c_ulong)
    ]

# /* CK_RSA_PKCS_OAEP_PARAMS is new for v2.10.
#  * CK_RSA_PKCS_OAEP_PARAMS provides the parameters to the
#  * CKM_RSA_PKCS_OAEP mechanism. */
# typedef struct CK_RSA_PKCS_OAEP_PARAMS {
#         CK_MECHANISM_TYPE hashAlg;
#         CK_RSA_PKCS_MGF_TYPE mgf;
#         CK_RSA_PKCS_OAEP_SOURCE_TYPE source;
#         CK_VOID_PTR pSourceData;
#         CK_ULONG ulSourceDataLen;
# } CK_RSA_PKCS_OAEP_PARAMS;
class CK_RSA_PKCS_OAEP_PARAMS(Structure):
    _fields_ = [
        ("hashAlg", c_ulong),
        ("mgf", c_ulong),
        ("source", c_ulong),
        ("pSourceData", c_void_p),
        ("ulSourceDataLen", c_ulong)
    ]

# typedef struct CK_AES_CBC_ENCRYPT_DATA_PARAMS {
#   CK_BYTE      iv[16];
#   CK_BYTE_PTR  pData;
#   CK_ULONG     length;
# } CK_AES_CBC_ENCRYPT_DATA_PARAMS;
# typedef CK_AES_CBC_ENCRYPT_DATA_PARAMS CK_PTR
# CK_AES_CBC_ENCRYPT_DATA_PARAMS_PTR;
class CK_AES_CBC_ENCRYPT_DATA_PARAMS(Structure):
    _fields_ = [
        ("iv", c_byte*16),
        ("pData", c_void_p),
        ("length", c_ulong)
    ]

# typedef struct CK_DERIVE_MASTER_KEY_PARAMS { 
#     unsigned int PCA2_secret_handle;
# 	unsigned int  seedLen;
# 	unsigned char *seed;
# } CK_DERIVE_MASTER_KEY_PARAMS;
class CK_DERIVE_MASTER_KEY_PARAMS(Structure):
    _fields_ = [
        ("PCA2_secret_handle", c_uint),
        ("seedLen", c_uint),
        ("seed", c_void_p)
    ]

# typedef struct CK_KEY_DERIVATION_STRING_DATA {
#   CK_BYTE_PTR pData;
#   CK_ULONG    ulLen;
# } CK_KEY_DERIVATION_STRING_DATA;

class CK_KEY_DERIVATION_STRING_DATA(Structure):
    _fields_ = [
        ("pData", c_void_p),
        ("ulLen", c_ulong)
    ]

# typedef struct CK_SESSION_INFO {
#   CK_SLOT_ID slotID;
#   CK_STATE state;
#   CK_FLAGS flags;
#   CK_ULONG ulDeviceError;
# } CK_SESSION_INFO;
class CK_SESSION_INFO(Structure):
    _fields_ = [
        ("slotID", c_ulong),
        ("state", c_ulong),
        ("flags", c_ulong),
        ("ulDeviceError", c_ulong)
    ]

    def get_state(self):
        return SessionState(self.state)

    def get_flags(self):
        return [sf for sf in SessionFlag if sf in SessionFlag(self.flags)]

# typedef struct CK_MECHANISM_INFO {
#     CK_ULONG    ulMinKeySize;
#     CK_ULONG    ulMaxKeySize;
#     CK_FLAGS    flags;
# } CK_MECHANISM_INFO;

class CK_MECHANISM_INFO(Structure):
    _fields_ = [
        ("ulMinKeySize", c_ulong),
        ("ulMaxKeySize", c_ulong),
        ("flags", c_ulong)
    ]

    def get_flags(self):
        return [sf for sf in MechanismFlag if sf in MechanismFlag(self.flags)]

# typedef struct CK_SP800_108_COUNTER_FORMAT {
#     CK_ULONG   ulWidthInBits;
# } CK_SP800_108_COUNTER_FORMAT;
class CK_SP800_108_COUNTER_FORMAT(Structure):
    _fields_ = [
        ("ulWidthInBits", c_ulong)
    ]

# typedef struct CK_SP800_108_DKM_LENGTH_FORMAT {
#     CK_ULONG  dkmLengthMethod;
#     CK_ULONG  ulWidthInBits;
# } CK_SP800_108_DKM_LENGTH_FORMAT;
class CK_SP800_108_DKM_LENGTH_FORMAT(Structure):
    _fields_ = [
        ("dkmLengthMethod", c_ulong),
        ("ulWidthInBits", c_ulong)
    ]

# typedef struct CK_PRF_DATA_PARAM {
#     CK_PRF_DATA_TYPE   type;
#     CK_VOID_PTR        pValue;
#     CK_ULONG           ulValueLen;
# } CK_PRF_DATA_PARAM;
class CK_PRF_DATA_PARAM(Structure):
    _fields_ = [
        ("type", c_ulong),
        ("pValue", c_void_p),
        ("ulValueLen", c_ulong)
    ]

    @classmethod
    def construct(cls, atype, value=None):
        assert isinstance(atype, PrfDataType)
        p, s = get_void_pointer_and_len(value)
        return cls(
            atype,
            p,
            s
        )

    @classmethod
    def get_array_of(cls, l):
        count = len(l)
        array = cls * count
        return array(*l)

# typedef struct CK_SP800_108_KDF_PARAMS {
#     CK_PRF_TYPE            prftype;
#     CK_ULONG               ulNumberOfDataParams;
#     CK_PRF_DATA_PARAM_PTR  pDataParams;
# } CK_SP800_108_KDF_PARAMS;
class CK_SP800_108_KDF_PARAMS(Structure):
    _fields_ = [
        ("prftype", c_ulong),
        ("ulNumberOfDataParams", c_ulong),
        ("pDataParams", c_void_p)
    ]


# typedef struct CK_C_INITIALIZE_ARGS {
#   CK_CREATEMUTEX CreateMutex;
#   CK_DESTROYMUTEX DestroyMutex;
#   CK_LOCKMUTEX LockMutex;
#   CK_UNLOCKMUTEX UnlockMutex;
#   CK_FLAGS flags;
#   CK_VOID_PTR pReserved;
# } CK_C_INITIALIZE_ARGS;
class CK_C_INITIALIZE_ARGS(Structure):
    _fields_ = [
        ("CreateMutex", c_void_p),
        ("DestroyMutex", c_void_p),
        ("LockMutex", c_void_p),
        ("UnlockMutex", c_void_p),
        ("flags", c_ulong),
        ("pReserved", c_void_p),
    ]

# typedef struct CK_VERSION {
#   CK_BYTE major;
#   CK_BYTE minor;
# } CK_VERSION;
class CK_VERSION(Structure):
    _fields_ = [
        ("major", c_byte),
        ("minor", c_byte)
    ]

# typedef struct CK_FUNCTION_LIST {
#   CK_VERSION version;
#   CK_C_Initialize C_Initialize;
#   CK_C_Finalize C_Finalize;
#   CK_C_GetInfo C_GetInfo;
#   CK_C_GetFunctionList C_GetFunctionList;
#   CK_C_GetSlotList C_GetSlotList;
#   CK_C_GetSlotInfo C_GetSlotInfo;
#   CK_C_GetTokenInfo C_GetTokenInfo;
#   CK_C_GetMechanismList C_GetMechanismList;
#   CK_C_GetMechanismInfo C_GetMechanismInfo;
#   CK_C_InitToken C_InitToken;
#   CK_C_InitPIN C_InitPIN;
#   CK_C_SetPIN C_SetPIN;
#   CK_C_OpenSession C_OpenSession;
#   CK_C_CloseSession C_CloseSession;
#   CK_C_CloseAllSessions C_CloseAllSessions;
#   CK_C_GetSessionInfo C_GetSessionInfo;
#   CK_C_GetOperationState C_GetOperationState;
#   CK_C_SetOperationState C_SetOperationState;
#   CK_C_Login C_Login;
#   CK_C_Logout C_Logout;
#   CK_C_CreateObject C_CreateObject;
#   CK_C_CopyObject C_CopyObject;
#   CK_C_DestroyObject C_DestroyObject;
#   CK_C_GetObjectSize C_GetObjectSize;
#   CK_C_GetAttributeValue C_GetAttributeValue;
#   CK_C_SetAttributeValue C_SetAttributeValue;
#   CK_C_FindObjectsInit C_FindObjectsInit;
#   CK_C_FindObjects C_FindObjects;
#   CK_C_FindObjectsFinal C_FindObjectsFinal;
#   CK_C_EncryptInit C_EncryptInit;
#   CK_C_Encrypt C_Encrypt;
#   CK_C_EncryptUpdate C_EncryptUpdate;
#   CK_C_EncryptFinal C_EncryptFinal;
#   CK_C_DecryptInit C_DecryptInit;
#   CK_C_Decrypt C_Decrypt;
#   CK_C_DecryptUpdate C_DecryptUpdate;
#   CK_C_DecryptFinal C_DecryptFinal;
#   CK_C_DigestInit C_DigestInit;
#   CK_C_Digest C_Digest;
#   CK_C_DigestUpdate C_DigestUpdate;
#   CK_C_DigestKey C_DigestKey;
#   CK_C_DigestFinal C_DigestFinal;
#   CK_C_SignInit C_SignInit;
#   CK_C_Sign C_Sign;
#   CK_C_SignUpdate C_SignUpdate;
#   CK_C_SignFinal C_SignFinal;
#   CK_C_SignRecoverInit C_SignRecoverInit;
#   CK_C_SignRecover C_SignRecover;
#   CK_C_VerifyInit C_VerifyInit;
#   CK_C_Verify C_Verify;
#   CK_C_VerifyUpdate C_VerifyUpdate;
#   CK_C_VerifyFinal C_VerifyFinal;
#   CK_C_VerifyRecoverInit C_VerifyRecoverInit;
#   CK_C_VerifyRecover C_VerifyRecover;
#   CK_C_DigestEncryptUpdate C_DigestEncryptUpdate;
#   CK_C_DecryptDigestUpdate C_DecryptDigestUpdate;
#   CK_C_SignEncryptUpdate C_SignEncryptUpdate;
#   CK_C_DecryptVerifyUpdate C_DecryptVerifyUpdate;
#   CK_C_GenerateKey C_GenerateKey;
#   CK_C_GenerateKeyPair C_GenerateKeyPair;
#   CK_C_WrapKey C_WrapKey;
#   CK_C_UnwrapKey C_UnwrapKey;
#   CK_C_DeriveKey C_DeriveKey;
#   CK_C_SeedRandom C_SeedRandom;
#   CK_C_GenerateRandom C_GenerateRandom;
#   CK_C_GetFunctionStatus C_GetFunctionStatus;
#   CK_C_CancelFunction C_CancelFunction;
#   CK_C_WaitForSlotEvent C_WaitForSlotEvent;
# } CK_FUNCTION_LIST;

# TODO: Add the real Functions signature insteaf of c_void_p
# For exemple, instead of
# ("C_OpenSession", c_void_p),
# We should have something like:
# ("C_OpenSession", CFUNCTYPE(c_ulong, c_ulong, c_ulong, c_void_p, c_void_p, c_void_p)),
# And this should be done for every function
class CK_FUNCTION_LIST(Structure):
    _fields_ = [
        ("version", CK_VERSION),
        ("C_Initialize", c_void_p),
        ("C_Finalize", c_void_p),
        ("C_GetInfo", c_void_p),
        ("C_GetFunctionList", c_void_p),
        ("C_GetSlotList", c_void_p),
        ("C_GetSlotInfo", c_void_p),
        ("C_GetTokenInfo", c_void_p),
        ("C_GetMechanismList", c_void_p),
        ("C_GetMechanismInfo", c_void_p),
        ("C_InitToken", c_void_p),
        ("C_InitPIN", c_void_p),
        ("C_SetPIN", c_void_p),
        ("C_OpenSession", c_void_p),
        ("C_CloseSession", c_void_p),
        ("C_CloseAllSessions", c_void_p),
        ("C_GetSessionInfo", c_void_p),
        ("C_GetOperationState", c_void_p),
        ("C_SetOperationState", c_void_p),
        ("C_Login", c_void_p),
        ("C_Logout", c_void_p),
        ("C_CreateObject", c_void_p),
        ("C_CopyObject", c_void_p),
        ("C_DestroyObject", c_void_p),
        ("C_GetObjectSize", c_void_p),
        ("C_GetAttributeValue", c_void_p),
        ("C_SetAttributeValue", c_void_p),
        ("C_FindObjectsInit", c_void_p),
        ("C_FindObjects", c_void_p),
        ("C_FindObjectsFinal", c_void_p),
        ("C_EncryptInit", c_void_p),
        ("C_Encrypt", c_void_p),
        ("C_EncryptUpdate", c_void_p),
        ("C_EncryptFinal", c_void_p),
        ("C_DecryptInit", c_void_p),
        ("C_Decrypt", c_void_p),
        ("C_DecryptUpdate", c_void_p),
        ("C_DecryptFinal", c_void_p),
        ("C_DigestInit", c_void_p),
        ("C_Digest", c_void_p),
        ("C_DigestUpdate", c_void_p),
        ("C_DigestKey", c_void_p),
        ("C_DigestFinal", c_void_p),
        ("C_SignInit", c_void_p),
        ("C_Sign", c_void_p),
        ("C_SignUpdate", c_void_p),
        ("C_SignFinal", c_void_p),
        ("C_SignRecoverInit", c_void_p),
        ("C_SignRecover", c_void_p),
        ("C_VerifyInit", c_void_p),
        ("C_Verify", c_void_p),
        ("C_VerifyUpdate", c_void_p),
        ("C_VerifyFinal", c_void_p),
        ("C_VerifyRecoverInit", c_void_p),
        ("C_VerifyRecover", c_void_p),
        ("C_DigestEncryptUpdate", c_void_p),
        ("C_DecryptDigestUpdate", c_void_p),
        ("C_SignEncryptUpdate", c_void_p),
        ("C_DecryptVerifyUpdate", c_void_p),
        ("C_GenerateKey", c_void_p),
        ("C_GenerateKeyPair", c_void_p),
        ("C_WrapKey", c_void_p),
        ("C_UnwrapKey", c_void_p),
        ("C_DeriveKey", c_void_p),
        ("C_SeedRandom", c_void_p),
        ("C_GenerateRandom", c_void_p),
        ("C_GetFunctionStatus", c_void_p),
        ("C_CancelFunction", c_void_p),
        ("C_WaitForSlotEvent", c_void_p)
    ]
