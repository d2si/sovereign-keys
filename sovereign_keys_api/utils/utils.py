#################
# Logger config #
#################
import logging
log_level = logging.DEBUG
# create logger
logger = logging.getLogger('custom')
logger.setLevel(log_level)
logger.propagate = False
# create console handler
ch = logging.StreamHandler()
ch.setLevel(log_level)
# create formatter
formatter = logging.Formatter('[%(asctime)s][%(threadName)s]%(levelname)s - %(message)s')
# add formatter to ch
ch.setFormatter(formatter)
# add ch to logger
logger.addHandler(ch)


#########
# UTILS #
#########
import base64
def b64_to_bin(b64_str):
    return base64.standard_b64decode(b64_str)

def bin_to_b64(bin_obj):
    return base64.standard_b64encode(bin_obj).decode()

import rsa
def extract_modulus_and_exp_from_der(der_encoded_pub_key):
    try:
        pub = rsa.PublicKey.load_pkcs1_openssl_der(der_encoded_pub_key)
    except:
        raise Exception('Not an RSA public key')
    mod = pub.n.to_bytes(513, 'big').lstrip(b'\x00')
    exp = pub.e.to_bytes(4, 'big').lstrip(b'\x00')
    return mod, exp

def compute_aad(kv_table):
    """Encode the Authentication data in a consistent way"""
    assert isinstance(kv_table, dict)
    keys = sorted(kv_table.keys())
    aad = bytearray(b'AAD:')
    for k in keys:
        aad.extend(k.lower().encode())
        aad.extend(kv_table[k].lower().encode())
    return bytes(aad)

def sig_to_der(rs_sig):
    assert len(rs_sig) == 96
    r = rs_sig[:48]
    s = rs_sig[48:]
    if r[0] & 128 != 0:
        r = b'\x00' + r
    if s[0] & 128 != 0:
        s = b'\x00' + s
    intr = b'\x02' + len(r).to_bytes(1, 'big') + r
    ints = b'\x02' + len(s).to_bytes(1, 'big') + s
    seq = intr + ints
    return b'\x30' + len(seq).to_bytes(1, 'big') + seq

# Generic HTTP exception
class HTTPError(Exception):
    def __init__(self, code, message):
        self.code = code
        self.message = message
