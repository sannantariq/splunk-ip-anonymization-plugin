# splunk-ip-anonymization-plugin
This is an external lookup script to perform prefix preserving anonymization on Splunk indexed datasets.

## Installation

### Prerequisites

- CentOS 7 or similar linux environment
- Python 2.7 or higher
- GCC or other C compiler
- Splunk instance ([Splunk installation instructions])
- OpenSSL development headers: `sudo yum install openssl-devel`
- CryptopANT Library ([Download Here])

### Installation Instructions

#### Installing CryptopANT

1. Download CryptopANT library from the link above.
2. UnTar the archive
3. Enter the directory: `$cd $CRYPTOPANT`
4. Run configuration script: `$./configure`
5. Run Makefile: `$make`
6. Make sure the shared library `$CRYPTOPANT/.libs/libcryptopANT.so.1` has been created. We will refer to this path as `$LIBCRYPTO_PATH`.

#### Testing Script

1. You can run some bare bones test without plugging into Splunk using the testing script provided.
2. Invoke testing script with `$python splunk-ip-anonymization-plugin/src/test/test_ip_anonymize.py $LIBCRYPTO_PATH`

#### Installing External Lookup Script

1. Choose where you want to place the external lookup script. Splunk allows you to choose between `$SPLUNK_HOME/etc/searchscripts/` or `$SPLUNK_HOME/etc/apps/app_name/bin/` as the script location.
2. Copy the script `ip_anonymize.py` into the Splunk script location.
3. Log in to Splunk Web UI -> Settings -> Lookups -> Lookup Definitions -> New Lookup Definition
4. Destination App: `Search`
5. Name: `myFancyLookup`
6. Type: `External`
7. Command: `ip_anonymize.py <path_to_key> $LIBCRYPTO_PATH ip_1 ip_2 ip_1_anon ip_2_anon`
8. Supported Fields: `ip_1,ip_2,ip_1_anon,ip_2_anon`

Please note that the key file will be created if it does not exist.

### Usage Instructions

This lookup can be invoked in a splunk query on a Zeek generated connection log as follows:

```sql
source="crc_splunk_2020-02-25_128.237.214.139.csv" | table * | lookup myFancyLookup ip_1 as id_orig_h ip_2 as id_resp_h OUTPUT ip_1_anon as id_orig_h ip_2_anon as id_resp_h
```
This should return the logs with the source and destination IP addresses replaced by their anonymized pseudonyms.

[Splunk installation instructions]: https://docs.splunk.com/Documentation/Splunk/8.0.3/Installation/InstallonLinux
[Download Here]: https://ant.isi.edu/software/cryptopANT/index.html