import socket
import binascii

class DHCPPayload:
    def __init__(self, 
                 opt, 
                 htype,
                 hlen,
                 hops,
                 trans_id,
                 se,
                 flags,
                 ciaddr,
                 yiaddr,
                 siaddr,
                 giaddr,
                 chaddr,
                 sname,
                 bname,
                 mcookie,
                 option_53,
                 option_51,
                 option_1,
                 option_3,
                 option_6,
                 option_54,
                 option_125,
                 option_58,
                 option_59,
                 option_28,
                 option_255):
        self._opt = opt
        self._htype = htype
        self._hlen = hlen
        self._hops = hops
        self._trans_id = trans_id
        self._se = se
        self._flags = flags
        self._ciaddr = ciaddr
        self._yiaddr = yiaddr
        self._siaddr = siaddr
        self._giaddr = giaddr
        self._chaddr = chaddr
        self._sname = sname
        self._bname = bname
        self._mcookie = mcookie
        self._option_53 = option_53
        self._option_51 = option_51
        self._option_1 = option_1
        self._option_3 = option_3
        self._option_6 = option_6
        self._option_54 = option_54
        self._option_125 = option_125
        self._option_58 = option_58
        self._option_59 = option_59
        self._option_28 = option_28
        self._option_255 = option_255

    def get_bytes(self):
        return ( self._opt.to_bytes(1, 'little')
            + self._htype.to_bytes(1, 'little')
            + self._hlen.to_bytes(1, 'little')
            + self._hops.to_bytes(1, 'little')
            + self._trans_id + self.se.to_bytes(2, 'little')
            + self._flags.to_bytes(2, 'little')
            + socket.inet_pton(socket.AF_INET, self._ciaddr)
            + socket.inet_pton(socket.AF_INET, self._yiaddr)
            + socket.inet_pton(socket.AF_INET, self._siaddr)
            + socket.inet_pton(socket.AF_INET, self._giaddr)
            + binascii.unhexlify(self._chaddr)
            + self._sname.encode()
            + self._bname.encode()
            )
            
class EthernetPayload:
	def __init__(self, destination, source, type):
		self._destination = destination
		self._source = source
		self._type = type

class IPV4Payload:
    def __init__(self, version, hl, tos, identification, flags, ttl, protocol, header_checksum, source, destination, ip_option):
        self._version = version
        self._hl = hl
        self._tos = tos
        self._identification = identification
        self._flags = flags
        self._ttl = ttl
        self._protocol = protocol
        self._header_checksum = header_checksum
        self._source = source
        self._destination = destination
        self._ip_option = ip_option
