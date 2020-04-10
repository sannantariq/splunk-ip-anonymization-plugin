#!/usr/bin/env python

"""
ip_anonymize.py
================
The core script of the project
which will be used to interface
between the anonymization library
and Splunk.

Author: Sannan Tariq
Email: stariq AT cs DOT cmu DOT edu
"""

import csv
import sys
import ctypes
import logging
import socket
import struct

DISABLE_LOGGING = True
LOG_NAME = 'IP_anon_plugin'
LOG_FILE = '/var/tmp/%s.log' % LOG_NAME
LOG_LEVEL = logging.ERROR


logger = logging.getLogger(LOG_NAME)
logger.disabled = DISABLE_LOGGING

hdlr = logging.FileHandler(LOG_FILE)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr) 
logger.setLevel(LOG_LEVEL)
logger.info("Python version info: %s", str(sys.version_info))

class ScrambleAlgo():
    """
    This is an enum containing the various scrambling
    routines we can choose from.
    """
    SCRAMBLE_MD5 		= 0x01
    SCRAMBLE_BLOWFISH 	= 0x02
    SCRAMBLE_AES 		= 0x03
    SCRAMBLE_SHA1		= 0x04

def ip2long(ip_str):
    """
    Return the numerical representation of an IPv4 address string

    :param ip_str: string IPv4 Address

    :return: int Numerical Representation of IPv4 address

    .. warning:: The behavior for invalid strings is undefined

    .. seealso:: long2ip
    """
    return struct.unpack("!L", socket.inet_aton(ip_str))[0]

def long2ip(num):
    """
    Return the string representation of a numerical IPv4 address

    :param num: int Numerical Representation of IPv4 address

    :return: string IPv4 Address

    .. warning:: The behavior for invalid numbers is undefined

    .. seealso:: ip2long
    """
    return socket.inet_ntoa(struct.pack('!L', num))

def swap32(x):
    """
    Return the input in reversed byte order

    :param x: int The input you want to flip the byte order of

    :return: int x but with its byte order flipped
    """
    return (((x << 24) & 0xFF000000) |
            ((x <<  8) & 0x00FF0000) |
            ((x >>  8) & 0x0000FF00) |
            ((x >> 24) & 0x000000FF))

def create_init_fun(lib):
    """
    Return the initialization function for the DLL

    :param lib: ctypes.cdll object loaded using ctypes.cdll.LoadLibrary

    :return: python function to invoke the library initialization
    """
    init_fun = lib.scramble_init_from_file
    init_fun.restype = ctypes.c_int
    init_fun.argtypes = [ctypes.c_char_p, ctypes.c_uint, 
                            ctypes.c_uint, ctypes.POINTER(ctypes.c_int)]
    return init_fun

def create_anonymize_fun(lib):
    """
    Return the anonymization function from the DLL

    :param lib: ctypes.cdll object loaded using ctypes.cdll.LoadLibrary

    :return: python function to invoke the anonymization routine
    """
    anonymize = lib.scramble_ip4
    anonymize.restype = ctypes.c_int32
    anonymize.argtypes = [ctypes.c_uint32, ctypes.c_int]
    return anonymize

def anonymize_ipv4(anonymize_function, ip4_str):
    """
    Return the prefix-preserved  anonymized string representation
     of the IPv4 address string

    :param anonymize_function: python function to invoke shared 
                            library anonymization routine
    :param ip4_str: string IPv4 Address string

    :return: string IPv4 prefix preserved anonymized string
    """

    # Specify how many bits to scramble in IP Address
    BITS_TO_SCRAMBLE = 32
    assert(BITS_TO_SCRAMBLE <= 32)
    assert(BITS_TO_SCRAMBLE >= 0)

    # Create 32 bit mask to and with output
    mask = (1 << 32) - 1

    # Convert string to numerical representation and reverse byte order
    reversed_bytes = swap32(ip2long(ip4_str))

    # Get anonymized numerical representation from Shared Library function
    anonymized_result = (anonymize_function(
        reversed_bytes, 32 - BITS_TO_SCRAMBLE) & mask)

    # Reverse byte order and convert back to IPv4 string
    return long2ip(swap32(anonymized_result))
    
def initialize_anon(init_function, scramble_algo, key_file_path):
    """
    This function initializes the library to perform scrambling
    

    :param init_function: python function to invoke shared
                        library initialization routine
    :param scramble_algo: enum value The algorithm to be used
                        for scrambling
    :param key_file_path: string Path to the key file
                        (will be created if not present)

    :return: None
    """
    filename = ctypes.c_char_p(key_file_path.encode())
    r = init_function(filename, scramble_algo, scramble_algo, None)
    assert(r == 0), "Initialization Failed"


def reverse_str(s):
    """
    This is a function to reverse an input string. Solely used
    for debugging purposes.

    :param s: string
    
    :return: reversed(s)
    """
    return ''.join(reversed(s))

def main():
    if len(sys.argv) != 7:
        print("Usage: python ip_anonymize.py [path_to_key] [path_to_lib] \
[ip1 field] [ip2 field] [anon_1 field] [anon_2 field]")

        logger.error("Incorrect invokation used : %s", ''.join(map(str, sys.argv)))
        sys.exit(1)

    # Parse Command Line Args
    KEYPATH = sys.argv[1]
    LIBPATH = sys.argv[2]
    ip1field = sys.argv[3]
    ip2field = sys.argv[4]
    anonymizedfield_1 = sys.argv[5]
    anonymizedfield_2 = sys.argv[6]
    
    # Load Anonymization Library
    try:
        lib = ctypes.cdll.LoadLibrary(LIBPATH)
    except:
        logger.error('Could not load anonymization library at path: %s', LIBPATH)
        sys.exit(1)

    logger.debug("Anonymization Library Successfully loaded")

    # Load functions from library
    init_fun = create_init_fun(lib)
    anon_fun = create_anonymize_fun(lib)

    logger.debug("Function Prototypes Created")

    # Initialize anonymization with key
    try:
        initialize_anon(init_fun, ScrambleAlgo.SCRAMBLE_BLOWFISH, KEYPATH)
    except:
        logger.error("Could not initialize state with key file: %s", KEYPATH)
        sys.exit(1)

    logger.debug("Initialized State Successfully")    
    

    # Get splunk pipes
    infile = sys.stdin
    outfile = sys.stdout

    # Parse input table
    r = csv.DictReader(infile)
    header = r.fieldnames

    # Create output table
    w = csv.DictWriter(outfile, fieldnames=r.fieldnames)
    w.writeheader()

    for result in r:
        # For each row in input table, write a row with the given input anonymized according to ip
        if result[ip1field]:
            result[anonymizedfield_1] = anonymize_ipv4(anon_fun, result[ip1field])
        if result[ip2field]:
            result[anonymizedfield_2] = anonymize_ipv4(anon_fun, result[ip2field])

        w.writerow(result)

if __name__ == "__main__":
    main()
