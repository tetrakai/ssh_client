'''SSH utilities module.

Contains functions to convert data into the types required for the SSH protocol, as defined in
https://tools.ietf.org/html/rfc2440. Specifically, this module contains parse and generate functions
for:
 - bytes,
 - uint32s,
 - strings,
 - name_lists, and
 - mpints.

The parse functions in this list take an array of data, and an index from which to start parsing,
and return the index at which their data ended, and the data itself.

Example:
  To parse an mpint followed by a string, from the start of the array `data`

    index, my_mpint = parse_mpint(data, 0)
    index, my_string = parse_string(data, index)

This module also contains utility functions for generating secure random bytes (`random_bytes`), and
for getting 32 byte (256 bit) binary network order representations of numbers.
'''

# pylint: disable=missing-docstring

import struct

__all__ = [
    'parse_byte', 'generate_byte',
    'parse_uint32', 'generate_uint32',
    'parse_string', 'generate_string',
    'parse_name_list', 'generate_name_list',
    'parse_mpint', 'generate_mpint',
    'random_bytes', 'get_32_byte_repr'
]

def parse_byte(data, start_index):
  return (start_index + 1, struct.unpack('B', data[start_index])[0])

def generate_byte(value):
  return struct.pack('B', value)

def parse_uint32(data, start_index):
  return (start_index + 4, struct.unpack('>I', data[start_index:start_index + 4])[0])

def generate_uint32(value):
  return struct.pack('>I', value)

def parse_string(data, start_index):
  len_size = 4
  strlen = struct.unpack('>I', data[start_index:start_index + len_size])[0]
  start_index += len_size
  string = data[start_index:start_index + strlen]
  start_index += strlen
  return (start_index, string)

def generate_string(string):
  return struct.pack('>I', len(string)) + string

def parse_name_list(data, start_index):
  start_index, name_list = parse_string(data, start_index)

  return (start_index, name_list.split(','))

def generate_name_list(items):
  return generate_string(','.join(items))

def _bitflip_byte(data):
  return struct.pack('B', (~struct.unpack('B', data)[0]) % 0x100)

def _twos_complement(byte_array):
  byte_array = [_bitflip_byte(b) for b in byte_array]

  i = 0
  while byte_array[i] == '\xff':
    byte_array[i] = '\x00'
    i += 1
  byte_array[i] = struct.pack('B', struct.unpack('B', byte_array[i])[0] + 1)

  return byte_array

def parse_mpint(data, start_index):
  start_index, string = parse_string(data, start_index)
  num = 0

  negative = False
  if len(string) > 0:
    if struct.unpack('B', string[0])[0] >> 7 == 1:
      negative = True

  for char in string:
    if negative:
      char = _bitflip_byte(char)
    num = (num << 8) + struct.unpack('B', char)[0]

  if negative:
    num = -(num + 1)

  return (start_index, num)

def generate_mpint(num):
  negative = False
  if num < 0:
    num = -num
    negative = True

  string = []
  if num != 0:
    while num / 256 > 0:
      string.append(struct.pack('B', num % 256))
      num /= 256
    string.append(struct.pack('B', num % 256))

    # If the highest bit *should* be set
    if (num % 256) >> 7 == 1:
      string.append('\x00')

    # If the highest bit is set, add a zero padding byte
    if negative:
      string = _twos_complement(string)

  return generate_string(''.join(reversed(string)))

def random_bytes(num_bytes):
  return open('/dev/urandom').read(num_bytes)

def get_32_byte_repr(num):
  return struct.pack(
      '>QQQQ',
      (num & (0xffffffffffffffff << 192)) >> 192,
      (num & (0xffffffffffffffff << 128)) >> 128,
      (num & (0xffffffffffffffff << 64)) >> 64,
      (num & 0xffffffffffffffff)
  )
