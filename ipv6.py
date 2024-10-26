import socket


def get_ipv6_mask(length: int) -> bytes:
	bits_mask = "1" * length + "0" * (128 - length)
	return int(bits_mask, 2).to_bytes((len(bits_mask) + 7) // 8, byteorder="big")


def get_ipv6_prefix(ipv6_addr: str|bytes, prefix_length: int, as_string: bool = True) -> bytearray|str:
	if type(ipv6_addr) == str:
		ipv6_addr = socket.inet_pton(socket.AF_INET6, ipv6_addr)
	
	hex_mask = get_ipv6_mask(prefix_length)
	ipv6_prefix = bytearray()
	for i in range(16):
		ipv6_prefix.append(ipv6_addr[i] & hex_mask[i])

	if as_string:
		ipv6_prefix = socket.inet_ntop(socket.AF_INET6, ipv6_prefix)
	return ipv6_prefix


def replace_ipv6_prefix(ipv6_addr: str|bytes, new_prefix: str|bytes, prefix_length: int) -> str:
	if type(ipv6_addr) == str:
		ipv6_addr = socket.inet_pton(socket.AF_INET6, ipv6_addr)
	if type(new_prefix) == str:
		new_prefix = socket.inet_pton(socket.AF_INET6, new_prefix)
	
	
	hex_mask = get_ipv6_mask(prefix_length)
	ipv6_prefix = bytearray()
	for i in range(16):
		inverted_mask_byte = hex_mask[i] ^ 0xff
		ipv6_prefix.append((new_prefix[i] & hex_mask[i]) | (ipv6_addr[i] & inverted_mask_byte))
	
	ipv6_prefix = socket.inet_ntop(socket.AF_INET6, ipv6_prefix)
	return ipv6_prefix


def has_ipv6_prefix(ipv6_addr: str|bytes, prefix: str|bytes, prefix_length: int) -> bool:
	if type(ipv6_addr) == str:
		ipv6_addr = socket.inet_pton(socket.AF_INET6, ipv6_addr)
	if type(prefix) == str:
		prefix = socket.inet_pton(socket.AF_INET6, prefix)
	
	hex_mask = get_ipv6_mask(prefix_length)
	prefix1 = bytearray()
	prefix2 = bytearray()
	for i in range(16):
		prefix1.append(ipv6_addr[i] & hex_mask[i])
		prefix2.append(prefix[i] & hex_mask[i])
	
	return prefix1 == prefix2
