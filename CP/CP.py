from crccheck.crc import Crc32, CrcXmodem, Crc16Genibus, Crc32c
from crccheck.checksum import Checksum32
import numpy as np
import bitarray
import struct
import binascii
import csv
import math

SERVERNAME_MAX_LEN = 31
SERVERNAME_LENGTH_BITS = SERVERNAME_MAX_LEN * 8 # = 248

def str_to_binary(servername):
    ba = bitarray.bitarray()
    ba.frombytes(servername.encode('utf-8'))
    return ba.tolist()

def bitstring_to_bytes(s):
    '''
    From string of bits to bytearray
    '''
    return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder='big')

def calc_crc_32_servername(servername):
    part2 = [2, 3, 6, 7, 10, 11, 14, 15, 18, 19, 22, 23, 26, 27, 30, 31]
    part4 = [4, 5, 6, 7, 12, 13, 14, 15, 20, 21, 22, 23, 28, 29, 30, 31]
    part8 = [8, 9, 10, 11, 12, 13, 14, 15, 24, 25, 26, 27, 28, 29, 30, 31]
    part16 = [16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]
    full_servername = np.zeros((SERVERNAME_LENGTH_BITS))
    bit_index = SERVERNAME_LENGTH_BITS
    start_index = 0
    final_hash = ""

    if len(servername) > 31: 
        return -1

    if len(servername) % 2 != 0: 
        parse_chars = servername[start_index]
        full_servername[bit_index - 8: bit_index] = str_to_binary(parse_chars)        
        start_index += 1 # 1 char parsed
    bit_index -= 8
    
    if len(servername) in part2:
        parse_chars = ''.join(servername[start_index: start_index + 2])
        full_servername[bit_index - 16: bit_index] = str_to_binary(parse_chars)
        start_index += 2 # 2 chars parsed
    bit_index -= 16

    if len(servername) in part4:
        parse_chars = ''.join(servername[start_index: start_index + 4])
        full_servername[bit_index - 32: bit_index] = str_to_binary(parse_chars)
        start_index += 4 # 4 chars parsed
    bit_index -= 32

    if len(servername) in part8:
        parse_chars = ''.join(servername[start_index: start_index + 8])
        full_servername[bit_index - 64: bit_index] = str_to_binary(parse_chars)
        start_index += 8 # 8 chars parsed
    bit_index -= 64

    if len(servername) in part16:
        parse_chars = ''.join(servername[start_index: start_index + 16])
        full_servername[bit_index - 128: bit_index] = str_to_binary(parse_chars)
        start_index += 16 # 16 chars parsed
    bit_index -= 128 


    full_servername = [str(int(a)) for a in full_servername]
    full_servername = ''.join(list(full_servername))
    binary = bitstring_to_bytes(full_servername)
    crc32_c = Crc32c()
    crc32_c.process(binary)
    final_hash = crc32_c.finalhex()
    

    return final_hash

    
t = calc_crc_32_servername("example.ulfheim.net")
t = calc_crc_32_servername("google.com")
t = calc_crc_32_servername("facebook.com")

print(t)
