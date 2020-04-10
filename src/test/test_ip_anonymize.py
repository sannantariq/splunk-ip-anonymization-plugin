#!/usr/bin/env python

"""
This module can be used to 
test the anonymization script
without plugging into splunk.

Author: Sannan Tariq
Email: stariq AT cs DOT cmu DOT edu
"""

import socket
import struct
import os
import csv
import sys
import subprocess



def ip2long(ip_str):
    """
    Return the numerical representation of an IPv4 address string

    :param ip_str: string IPv4 Address

    :return: int Numerical Representation of IPv4 address

    .. warning:: The behavior for invalid strings is undefined

    .. seealso:: long2ip
    """
    return struct.unpack("!L", socket.inet_aton(ip_str))[0]

def common_prefix_len(ip_a, ip_b):
    return 32 - (ip_a ^ ip_b).bit_length()

def check_prefix_preservation(ip_a, ip_b, anon_a, anon_b):
    return common_prefix_len(ip2long(ip_a), ip2long(ip_b)) == common_prefix_len(ip2long(anon_a), ip2long(anon_b))

def main():

    if len(sys.argv) != 2:
        print("Usage: python test_ip_anonymize.py /path/to/shared/library")
        sys.exit(1)


    CUR_DIR = os.path.dirname(os.path.abspath(__file__)) + "/"
    TEST_INPUT_PATH = CUR_DIR + "test_input.csv"
    REFERENCE_OUTPUT_PATH = CUR_DIR + "test_output.csv"
    KEY_PATH = CUR_DIR +  "test_key.key"
    LIB_PATH = sys.argv[1]
    ANONYMIZATION_SCRIPT_PATH = CUR_DIR + "../ip_anonymize.py"
    SCRIPT_ARGS = [
        "python",
        ANONYMIZATION_SCRIPT_PATH,
        KEY_PATH,
        LIB_PATH,
        "id_orig_h",
        "id_resp_h",
        "ip_1_anon",
        "ip_2_anon"
    ]

    with open(REFERENCE_OUTPUT_PATH) as f:
        output_reference = [r for r in csv.DictReader(f)]

    print("Running Anonymization Code")

    try:
        with open(TEST_INPUT_PATH) as f:
            p = subprocess.Popen(SCRIPT_ARGS, stdin=f, stdout=subprocess.PIPE)
            output_generated = [r for r in csv.DictReader(p.stdout)]
            if p.returncode == 1:
                print("Anonymization Script Exited with Status code 1. Check Logs.")
    except:
        print("Anonymization Script Failed to open or failed unexpectedly. Check Logs.")
        sys.exit(1)
    
    print("Anonymization Exited Succesfully")

    print("Test 1: Checking Prefix Preservation in Generated Output")

    # Test Prefix Preservation in generated output
    for gen in output_generated:
        if not check_prefix_preservation(gen['id_orig_h'], gen['id_resp_h'], gen['ip_1_anon'], gen['ip_2_anon']):
            print("Prefix not preserved for line: %s" % (str(gen)))
            assert(False)
    print("Tests 1/2 Passed!")

    # Match generated output with reference
    print("Test 2: Checking against reference output")

    if not len(output_generated) == len(output_reference):
        print("Length of file does not match")
        assert(False)

    for gen, ref in zip(output_generated, output_reference):
        if not len(list(gen.keys())) == len(list(ref.keys())):
            print("Length of lines does not match")
            assert(False)
        for k, v in gen.items():
            if v != ref[k]:
                print("Mismatching Fields: %s != %s" % (v, ref[k]))
                assert(False)
    
    print("Tests 2/2 Passed!")


if __name__ == "__main__":
    main()
