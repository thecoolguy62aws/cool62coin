"""Minimal Bech32/Bech32m codec (BIP173/BIP350)."""

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_CONST = 1
BECH32M_CONST = 0x2BC830A3


def _polymod(values):
    generators = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i in range(5):
            if (top >> i) & 1:
                chk ^= generators[i]
    return chk


def _hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _create_checksum(hrp, data, const):
    values = _hrp_expand(hrp) + list(data)
    polymod = _polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _verify_checksum(hrp, data, const):
    return _polymod(_hrp_expand(hrp) + list(data)) == const


def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def encode(hrp, data, const=BECH32M_CONST):
    combined = list(data) + _create_checksum(hrp, data, const)
    return hrp + "1" + "".join(CHARSET[d] for d in combined)


def decode(address, const=BECH32M_CONST):
    if not isinstance(address, str):
        raise ValueError("address must be a string")
    if any(ord(c) < 33 or ord(c) > 126 for c in address):
        raise ValueError("invalid character in address")
    if address.lower() != address and address.upper() != address:
        raise ValueError("mixed-case address")
    address = address.lower()
    pos = address.rfind("1")
    if pos < 1 or pos + 7 > len(address) or len(address) > 90:
        raise ValueError("invalid Bech32 address")
    hrp = address[:pos]
    try:
        data = [CHARSET.index(c) for c in address[pos + 1:]]
    except ValueError:
        raise ValueError("invalid Bech32 character") from None
    if not _verify_checksum(hrp, data, const):
        raise ValueError("address checksum mismatch")
    return hrp, data[:-6]
