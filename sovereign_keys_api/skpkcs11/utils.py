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
