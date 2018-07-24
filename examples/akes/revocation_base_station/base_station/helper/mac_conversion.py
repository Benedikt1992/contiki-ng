
def MAC_string_to_byte(mac_addr):
    result = b''
    for group in mac_addr.split('.'):
        result += bytes.fromhex(group)
    return result


def MAC_byte_to_string(mac_addr):
    result = mac_addr.hex()
    t = iter(result)

    result = '.'.join(a+b+c+d for a,b,c,d in zip(t,t,t,t))

    return result


def MAC_bytearray_to_stringarray(mac_addrs):
    result = []
    if not mac_addrs:
        return result
    for mac_addr in mac_addrs:
        result.append(MAC_byte_to_string(mac_addr))

    return result
