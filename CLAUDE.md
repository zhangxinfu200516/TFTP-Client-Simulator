# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

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

## Architecture

The script is a single file with four layers, read top-to-bottom:

1. **Constants** — TFTP opcodes (1–5) and error codes (0–7), `ERROR_NAMES` mapping.
2. **Logging** — `_setup_logging()` and `log_packet()` for timestamped output with optional hex dump.
3. **Packet layer** — `pack_rrq_wrq()`, `pack_data()`, `pack_ack()`, `pack_error()`, `unpack_packet()`. All use `struct.pack("!H", ...)` for network byte order. `pack_rrq_wrq` appends a `blksize` option when non-zero.
4. **`TftpClient`** — The core class. Holds `server`, `port`, `timeout`, `max_retries`, `blksize`, `mode`, and tracks `server_ephemeral_port` (the TID port the server opens for data transfer, distinct from port 69).

### TFTP Protocol Flow

- **Port 69** is used only for the initial RRQ/WRQ. All subsequent DATA/ACK exchange happens on the server's ephemeral port, which the client learns from the first response.
- Block numbers are 16-bit, wrapping at 65535 (`block_num & 0xFFFF`).

**WRQ (upload, `send_file`):**
1. Send WRQ to server:69 → wait for ACK(0) from ephemeral port (uses `_retry_send_recv` with retry).
2. Read file in `blksize` chunks → send DATA(1), DATA(2), ...; wait for matching ACK after each.
3. Last chunk `< blksize` signals end of transfer.

**RRQ (download, `receive_file`):**
1. Send RRQ to server:69 → loop `recvfrom` for DATA packets.
2. Write payload to local file, reply ACK(block_num).
3. Packet `< blksize` signals last block. Duplicate DATA blocks (same `block_num` as last) trigger ACK retransmission only.

### Key Methods on TftpClient

| Method | Purpose |
|--------|---------|
| `_retry_send_recv()` | Send a packet, retry on timeout, filter by expected opcode/block. Used for WRQ ACK(0) handshake. |
| `send_file(local, remote)` | Full WRQ upload — pre-checks file exists, sends WRQ, streams data blocks with per-block retry. |
| `receive_file(remote, local)` | Full RRQ download — sends RRQ, receives data blocks, writes file, handles duplicates. |

### Error Handling

- `TftpError` — raised on server ERROR packet (opcode 5), caught in `main()` → exit code 2.
- `socket.timeout` — per-packet timeout; causes retry (up to `max_retries`) or full transfer abort → exit code 3.
- Incomplete downloads are cleaned up (local file deleted) on error/timeout/interrupt.
- `KeyboardInterrupt` → exit code 130.
