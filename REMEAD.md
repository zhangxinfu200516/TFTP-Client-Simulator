## Project Overview

Single-file TFTP client simulator (`tftp_client.py`) implementing RFC 1350 — upload (WRQ) and download (RRQ) against a TFTP server like Tftpd64.

## Running

```bash
# Requires Python 3. Path is msys2 ucrt64 on this machine:
D:/Users_keil5/msys64/ucrt64/bin/python.exe tftp_client.py --help

# Upload
python tftp_client.py put <server_ip> <local_file> [remote_file] [-v] [-b 1024] [-t 10] [-r 5]

# Download
python tftp_client.py get <server_ip> <remote_file> [local_file] [-v] [--blksize 512]
```

No dependencies beyond the Python standard library.