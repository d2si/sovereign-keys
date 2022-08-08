from ctypes import c_void_p
from ctypes import c_char_p
from ctypes import c_wchar_p
from ctypes import c_ulong
from ctypes import c_bool
from ctypes import c_char
from ctypes import Structure

from ctypes import cast
from ctypes import sizeof
from ctypes import pointer
from ctypes import POINTER
from ctypes import create_string_buffer

DEFAULT_BUFFER_SIZE = 1000

def get_buffer(size=DEFAULT_BUFFER_SIZE):
    buf = create_string_buffer(size)
    buf_len = c_ulong(size)
    return buf, buf_len

def get_void_pointer_and_len(value):
    if isinstance(value, (c_void_p, c_char_p, c_wchar_p)):
        raise TypeError(f'value of type {type(value)} cannot be processed')
    # Maybe value is already a ctypes
    try:
        p = cast(pointer(value), c_void_p)
        s = sizeof(value)
        return (p, s)
    except TypeError:
        # No its not, just continue
        pass
    if value is None:
        p = None
        s = 0
    elif isinstance(value, bool):
        b = c_bool(value)
        p = cast(pointer(b), c_void_p)
        s = sizeof(b)
    elif isinstance(value, str):
        sbin = value.encode()
        p = cast(c_char_p(sbin), c_void_p)
        s = len(sbin)
    elif isinstance(value, bytes):
        p = cast(c_char_p(value), c_void_p)
        s = len(value)
    elif isinstance(value, int):
        ul = c_ulong(value)
        p = cast(pointer(ul), c_void_p)
        s = sizeof(ul)
    else:
        raise TypeError(f'value of type {type(value)} cannot be processed')
    return (p, s)

def get_value_from_void_pointer_and_len(value_type, ptr, ptr_len):
    if isinstance(ptr_len, c_ulong):
        ptr_len = ptr_len.value
    value_bytes = cast(ptr, POINTER(c_char*ptr_len)).contents[:ptr_len]
    if value_type is bool:
        return bool(value_bytes)
    elif value_type is int:
        return int.from_bytes(value_bytes, 'big')
    elif value_type is str:
        return value_bytes.decode()
    elif value_type is bytes:
        return value_bytes
    else:
        raise TypeError(f'value of type {value_type} cannot be processed')
