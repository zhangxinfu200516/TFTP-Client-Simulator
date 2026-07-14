#!/usr/bin/env python3
"""
TFTP Client Simulator — 与 TFTP 服务器（如 Tftpd64）进行文件上传/下载。

协议遵循 RFC 1350 (Trivial File Transfer Protocol)。

用法:
  python tftp_client.py put <server> <local_file> [remote_file] [options]
  python tftp_client.py get <server> <remote_file> [local_file] [options]

示例:
  python tftp_client.py put 127.0.0.1 test.bin -v
  python tftp_client.py get 127.0.0.1 test.bin output.bin -v --blksize 1024
"""

import argparse
import logging
import os
import socket
import struct
import sys
import time
from datetime import datetime

# ── TFTP Opcodes (RFC 1350) ──────────────────────────────────────────
OP_RRQ   = 1   # Read Request
OP_WRQ   = 2   # Write Request
OP_DATA  = 3   # Data
OP_ACK   = 4   # Acknowledgement
OP_ERROR = 5   # Error
OP_OACK  = 6   # Option Acknowledgment (RFC 2347)

# ── TFTP Error Codes ──────────────────────────────────────────────────
ERR_UNDEFINED    = 0
ERR_NOT_FOUND    = 1
ERR_ACCESS       = 2
ERR_DISK_FULL    = 3
ERR_ILLEGAL_OP   = 4
ERR_UNKNOWN_TID  = 5
ERR_FILE_EXISTS  = 6
ERR_NO_SUCH_USER = 7

ERROR_NAMES = {
    0: "未定义错误",
    1: "文件不存在",
    2: "访问拒绝",
    3: "磁盘已满",
    4: "非法操作",
    5: "未知传输ID",
    6: "文件已存在",
    7: "无此用户",
}

# 默认数据块大小 (RFC 1350)
DEFAULT_BLKSIZE = 512

# ── Logging ───────────────────────────────────────────────────────────
logger = logging.getLogger("tftp")
_default_handler = None
_verbose = False


def _setup_logging(verbose: bool):
    """配置日志：始终有时间戳+级别前缀。verbose 时显示 DEBUG，否则只显示 INFO。"""
    global _verbose, _default_handler
    _verbose = verbose
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    if _default_handler is None:
        _default_handler = logging.StreamHandler(sys.stdout)
        _default_handler.setFormatter(
            logging.Formatter(
                "[%(asctime)s.%(msecs)03d] %(levelname)-7s %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(_default_handler)


def log_packet(direction: str, pkt_type: str, data: bytes, peer: tuple = None):
    """记录数据包的 hex dump（仅 verbose 模式）"""
    if not _verbose:
        return
    peer_str = f" peer={peer[0]}:{peer[1]}" if peer else ""
    logger.debug("%s %s, size=%d%s", direction, pkt_type, len(data), peer_str)
    # hex dump: 每行 16 字节
    for offset in range(0, len(data), 16):
        chunk = data[offset : offset + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        logger.debug("  %04x  %-*s  %s", offset, 48, hex_part, ascii_part)


# ── Packet Builders / Parsers ─────────────────────────────────────────

def pack_rrq_wrq(opcode: int, filename: str, mode: str, blksize: int = 0) -> bytes:
    """构建 RRQ/WRQ 包。blksize > 0 时追加 blksize 选项。"""
    pkt = struct.pack("!H", opcode)
    pkt += filename.encode("ascii") + b"\x00"
    pkt += mode.encode("ascii") + b"\x00"
    if blksize > 0:
        pkt += b"blksize\x00" + str(blksize).encode("ascii") + b"\x00"
    return pkt


def pack_data(block_num: int, data: bytes) -> bytes:
    """构建 DATA 包。块号 16-bit，范围 1..65535。"""
    return struct.pack("!HH", OP_DATA, block_num) + data


def pack_ack(block_num: int) -> bytes:
    """构建 ACK 包。"""
    return struct.pack("!HH", OP_ACK, block_num)


def pack_error(error_code: int, msg: str) -> bytes:
    """构建 ERROR 包。"""
    return struct.pack("!HH", OP_ERROR, error_code) + msg.encode("ascii") + b"\x00"


def parse_oack_options(data: bytes) -> dict:
    """解析 OACK 包的选项字段，返回 {key: value} 字典。"""
    options = {}
    # data 是 opcode(2字节) 之后的部分
    rest = data[2:] if len(data) >= 2 and struct.unpack("!H", data[:2])[0] == OP_OACK else data
    parts = rest.split(b"\x00")
    for i in range(0, len(parts) - 1, 2):
        key = parts[i].decode("ascii", errors="replace").lower()
        value = parts[i + 1].decode("ascii", errors="replace")
        options[key] = value
    return options


def unpack_packet(data: bytes):
    """
    解析收到的 TFTP 包。
    Returns: (opcode, block_num_or_code, payload_bytes, msg_str)
    """
    if len(data) < 4:
        raise ValueError(f"包太短，无法解析: {len(data)} 字节")
    opcode = struct.unpack("!H", data[:2])[0]
    if opcode == OP_DATA:
        block_num = struct.unpack("!H", data[2:4])[0]
        payload = data[4:]
        return (opcode, block_num, payload, None)
    elif opcode == OP_ACK:
        block_num = struct.unpack("!H", data[2:4])[0]
        return (opcode, block_num, None, None)
    elif opcode == OP_ERROR:
        error_code = struct.unpack("!H", data[2:4])[0]
        # 错误消息以 null 结尾
        err_msg_bytes = data[4:]
        err_msg = err_msg_bytes.rstrip(b"\x00").decode("ascii", errors="replace")
        return (opcode, error_code, None, err_msg)
    elif opcode == OP_OACK:
        # 选项确认包 — 返回原始选项数据
        return (opcode, 0, data[2:], None)
    elif opcode in (OP_RRQ, OP_WRQ):
        # 客户端不应收到 RRQ/WRQ，但这里仍做解析
        return (opcode, 0, None, None)
    else:
        raise ValueError(f"未知操作码: {opcode}")


# ── UDP Socket Helpers ────────────────────────────────────────────────

def create_socket(timeout: float) -> socket.socket:
    """创建 UDP socket，绑定到系统自动分配的端口。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    return sock


def send_packet(sock: socket.socket, data: bytes, addr: tuple):
    """发送 UDP 数据包并记录日志。"""
    sock.sendto(data, addr)


def recv_packet(sock: socket.socket, bufsize: int = 65536) -> (bytes, tuple):
    """接收 UDP 数据包，返回 (data, addr)。"""
    return sock.recvfrom(bufsize)


# ── TFTP Client Core ──────────────────────────────────────────────────

class TftpError(Exception):
    """TFTP 协议错误。"""
    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message
        super().__init__(f"[错误 {code}] {message}")


class TftpClient:
    """TFTP 客户端，负责一次上传或下载的完整生命周期。"""

    def __init__(
        self,
        server: str,
        port: int = 69,
        timeout: float = 5.0,
        max_retries: int = 3,
        blksize: int = DEFAULT_BLKSIZE,
        mode: str = "octet",
    ):
        self.server = server
        self.port = port
        self.timeout = timeout
        self.max_retries = max_retries
        self.blksize = blksize
        self.mode = mode
        self.sock: socket.socket = None
        self.server_ephemeral_port = None  # 服务器用于传输数据的临时端口

    # ── send with retry ──────────────────────────────────────────────

    def _retry_send_recv(
        self,
        build_packet,
        expect_opcode: int,
        expect_block: int = None,
        initial_addr: tuple = None,
    ):
        """
        发送包并等待特定应答。支持超时自动重传。

        Args:
            build_packet(): 返回要发送的包的 callable
            expect_opcode: 期望收到的操作码
            expect_block: 期望收到的块号（可选）
            initial_addr: 目标地址，None 则使用 server_ephemeral_port 或默认 port

        Returns:
            unpack_packet 的返回值

        Raises:
            TftpError: 收到错误包
            socket.timeout: 超时
        """
        addr = initial_addr or (self.server, self.server_ephemeral_port or self.port)
        pkt = build_packet()

        for attempt in range(self.max_retries + 1):
            if attempt > 0:
                logger.warning("重试 %d/%d ...", attempt, self.max_retries)

            send_packet(self.sock, pkt, addr)

            while True:
                try:
                    data, peer = recv_packet(self.sock)
                except socket.timeout:
                    logger.warning("超时（%.1fs），未收到应答", self.timeout)
                    break  # 退出内层循环，进入下一次重试

                # 过滤非期望源地址的包
                if peer[0] != self.server:
                    logger.debug("忽略来自 %s 的包（非服务器地址）", peer)
                    continue

                try:
                    opcode, block_num, payload, err_msg = unpack_packet(data)
                except ValueError as e:
                    logger.warning("无法解析收到的包: %s", e)
                    continue

                if opcode == OP_ERROR:
                    raise TftpError(block_num, err_msg or ERROR_NAMES.get(block_num, "未知错误"))

                # 记录服务器临时端口（DATA/ACK/OACK 从临时端口来）
                if self.server_ephemeral_port is None and peer[1] != self.port:
                    self.server_ephemeral_port = peer[1]
                    logger.info("服务器数据端口: %d", self.server_ephemeral_port)

                if opcode == OP_OACK:
                    # 选项确认 — 解析并返回
                    options = parse_oack_options(data)
                    negotiated_blksize = int(options.get("blksize", self.blksize))
                    if negotiated_blksize != self.blksize:
                        logger.info("服务器协商 blksize: %d → %d", self.blksize, negotiated_blksize)
                        self.blksize = negotiated_blksize
                    log_packet("接收", "OACK", data, peer)
                    # 如果期望的是 ACK(0)，OACK 也接受 — 返回 OACK 结果
                    if expect_opcode == OP_ACK:
                        logger.info("收到 OACK（替代 ACK 0）")
                        return (OP_OACK, 0, data[2:], None)
                    # 否则继续等待
                    logger.debug("收到 OACK，但期望 opcode=%d，继续等待", expect_opcode)
                    continue

                if opcode == expect_opcode:
                    if expect_block is not None and block_num != expect_block:
                        # 收到非预期的块号（可能是重复的 DATA 包，重发 ACK）
                        logger.debug(
                            "收到非预期的块号 %d（期望 %d），可能为重复包",
                            block_num,
                            expect_block,
                        )
                        # 如果是重复旧包，重新确认旧的
                        if opcode == OP_DATA and block_num < (expect_block or 0):
                            ack = pack_ack(block_num)
                            send_packet(self.sock, ack, (self.server, peer[1]))
                            continue
                        # 否则忽略，继续等待
                        continue
                    return (opcode, block_num, payload, err_msg)

                logger.debug("收到操作码 %d，忽略（期望 %d）", opcode, expect_opcode)
                # 非期望的操作码，继续等待

        raise socket.timeout(f"重试 {self.max_retries} 次后仍未收到应答")

    # ── RRQ: Download ────────────────────────────────────────────────

    def receive_file(self, remote_file: str, local_file: str):
        """
        从 TFTP 服务器下载文件 (RRQ)。
        支持 RFC 2347 OACK 选项协商。
        """
        logger.info("═" * 60)
        logger.info("TFTP 下载 (RRQ)")
        logger.info("  服务器:    %s:%d", self.server, self.port)
        logger.info("  远程文件:  %s", remote_file)
        logger.info("  本地文件:  %s", local_file)
        logger.info("  传输模式:  %s", self.mode)
        logger.info("  块大小:    %d", self.blksize)
        logger.info("  超时:      %.1fs", self.timeout)
        logger.info("  最大重试:  %d", self.max_retries)
        logger.info("═" * 60)

        self.sock = create_socket(self.timeout)
        start_time = time.time()
        total_bytes = 0
        block_count = 0
        last_block = -1  # 用于检测重复 DATA 包
        finished = False

        try:
            # 1. 发送 RRQ
            logger.info("发送 RRQ 请求 ...")
            rrq = pack_rrq_wrq(OP_RRQ, remote_file, self.mode, self.blksize)
            log_packet("发送", "RRQ", rrq)
            send_packet(self.sock, rrq, (self.server, self.port))

            # 2. 打开本地文件准备写入
            f = open(local_file, "wb")

            try:
                # 3. 接收第一个响应（可能是 OACK 或 DATA(1)）
                first_pkt = True
                while True:
                    data, peer = self.sock.recvfrom(65536)

                    if peer[1] != self.port:
                        self.server_ephemeral_port = peer[1]

                    try:
                        opcode, block_num, payload, err_msg = unpack_packet(data)
                    except ValueError as e:
                        logger.warning("无法解析: %s", e)
                        continue

                    if opcode == OP_ERROR:
                        raise TftpError(block_num, err_msg or ERROR_NAMES.get(block_num, "未知错误"))

                    if opcode == OP_OACK:
                        # 服务器返回选项确认 → 解析并回发 ACK(0)
                        options = parse_oack_options(data)
                        negotiated_blksize = int(options.get("blksize", self.blksize))
                        if negotiated_blksize != self.blksize:
                            logger.info("服务器协商 blksize: %d → %d", self.blksize, negotiated_blksize)
                            self.blksize = negotiated_blksize
                        log_packet("接收", "OACK", data, peer)
                        logger.info("收到 OACK，发送 ACK(0)")
                        ack0 = pack_ack(0)
                        log_packet("发送", "ACK block=0", ack0)
                        send_packet(self.sock, ack0, (self.server, peer[1]))
                        continue  # 继续等待 DATA(1)

                    if opcode != OP_DATA:
                        logger.debug("忽略非 DATA 包: opcode=%d", opcode)
                        continue

                    # 处理 DATA 包
                    log_packet("接收", f"DATA block={block_num}, size={len(payload) if payload else 0}", data, peer)

                    # 检测重复包
                    if block_num == last_block:
                        logger.debug("收到重复 DATA block=%d，重发 ACK", block_num)
                        ack = pack_ack(block_num)
                        send_packet(self.sock, ack, (self.server, peer[1]))
                        continue

                    # 写入数据
                    if payload:
                        f.write(payload)
                        total_bytes += len(payload)
                    block_count += 1
                    last_block = block_num

                    # 发送 ACK
                    ack = pack_ack(block_num)
                    log_packet("发送", f"ACK block={block_num}", ack)
                    send_packet(self.sock, ack, (self.server, peer[1]))

                    logger.info(
                        "  进度: block=%d, size=%d, total=%d bytes",
                        block_num,
                        len(payload) if payload else 0,
                        total_bytes,
                    )

                    # 最后一个数据块（小于 blksize）
                    if payload and len(payload) < self.blksize:
                        logger.info("收到最后一个数据块（size=%d < blocksize=%d）", len(payload), self.blksize)
                        break

            finally:
                f.close()

            elapsed = time.time() - start_time
            speed = total_bytes / elapsed if elapsed > 0 else 0
            logger.info("═" * 60)
            logger.info("下载完成 ✓")
            logger.info("  文件大小:  %d bytes (%.2f KB)", total_bytes, total_bytes / 1024)
            logger.info("  数据块:    %d", block_count)
            logger.info("  用时:      %.2fs", elapsed)
            speed_str = (
                f"{speed / 1024:.1f} KB/s" if speed < 1024 * 1024 else f"{speed / 1024 / 1024:.1f} MB/s"
            )
            logger.info("  速率:      %s", speed_str)
            logger.info("═" * 60)

        except TftpError as e:
            logger.error("服务器返回错误: %s", e)
            if os.path.exists(local_file):
                try:
                    os.remove(local_file)
                except OSError:
                    pass
            raise
        except socket.timeout:
            logger.error("传输超时")
            if os.path.exists(local_file):
                try:
                    os.remove(local_file)
                except OSError:
                    pass
            raise
        except KeyboardInterrupt:
            logger.warning("用户中断传输")
            if os.path.exists(local_file):
                try:
                    os.remove(local_file)
                except OSError:
                    pass
            raise
        finally:
            self.sock.close()

    # ── WRQ: Upload ──────────────────────────────────────────────────

    def send_file(self, local_file: str, remote_file: str):
        """
        向 TFTP 服务器上传文件 (WRQ)。
        """
        # 预检查本地文件
        if not os.path.isfile(local_file):
            raise FileNotFoundError(f"本地文件不存在: {local_file}")
        file_size = os.path.getsize(local_file)

        logger.info("═" * 60)
        logger.info("TFTP 上传 (WRQ)")
        logger.info("  服务器:    %s:%d", self.server, self.port)
        logger.info("  本地文件:  %s", local_file)
        logger.info("  远程文件:  %s", remote_file)
        logger.info("  文件大小:  %d bytes (%.2f KB)", file_size, file_size / 1024)
        logger.info("  传输模式:  %s", self.mode)
        logger.info("  块大小:    %d", self.blksize)
        logger.info("  超时:      %.1fs", self.timeout)
        logger.info("  最大重试:  %d", self.max_retries)
        logger.info("═" * 60)

        self.sock = create_socket(self.timeout)
        start_time = time.time()
        total_bytes = 0
        block_count = 0

        try:
            # 1. 发送 WRQ
            logger.info("发送 WRQ 请求 ...")
            wrq = pack_rrq_wrq(OP_WRQ, remote_file, self.mode, self.blksize)
            log_packet("发送", "WRQ", wrq)

            send_packet(self.sock, wrq, (self.server, self.port))

            # 2. 等待 ACK(0) 或 OACK（带重试）
            oack_received = False
            for attempt in range(self.max_retries + 1):
                if attempt > 0:
                    logger.warning("重试 %d/%d ...", attempt, self.max_retries)
                    send_packet(self.sock, wrq, (self.server, self.port))

                try:
                    data, peer = self.sock.recvfrom(65536)
                    opcode, ack_block, payload, err_msg = unpack_packet(data)
                except socket.timeout:
                    logger.warning("超时（%.1fs），未收到应答", self.timeout)
                    continue

                if peer[0] != self.server:
                    continue

                if opcode == OP_ERROR:
                    raise TftpError(ack_block, err_msg or ERROR_NAMES.get(ack_block, "未知错误"))

                if peer[1] != self.port and self.server_ephemeral_port is None:
                    self.server_ephemeral_port = peer[1]
                    logger.info("服务器数据端口: %d", self.server_ephemeral_port)

                if opcode == OP_OACK:
                    options = parse_oack_options(data)
                    negotiated_blksize = int(options.get("blksize", self.blksize))
                    if negotiated_blksize != self.blksize:
                        logger.info("服务器协商 blksize: %d → %d", self.blksize, negotiated_blksize)
                        self.blksize = negotiated_blksize
                    log_packet("接收", "OACK", data, peer)
                    logger.info("服务器已确认选项 (OACK)")
                    oack_received = True
                    break

                if opcode == OP_ACK and ack_block == 0:
                    log_packet("接收", f"ACK block=0", data, peer)
                    logger.info("服务器已确认 WRQ (ACK 0)")
                    break

                logger.debug("收到非预期包: opcode=%d, block=%d", opcode, ack_block)
            else:
                raise socket.timeout("等待 WRQ 应答超时（重试 %d 次）" % self.max_retries)

            # 3. 发送文件数据
            block_num = 0
            with open(local_file, "rb") as f:
                while True:
                    block_num += 1
                    chunk = f.read(self.blksize)
                    # block_num 在 16-bit 范围内回绕
                    block_num_mod = block_num & 0xFFFF

                    data_pkt = pack_data(block_num_mod, chunk)
                    log_packet("发送", f"DATA block={block_num_mod}, size={len(chunk)}", data_pkt)

                    # 发送 DATA 并等待 ACK（带重试）
                    retry_ok = False
                    for attempt in range(self.max_retries + 1):
                        if attempt > 0:
                            logger.warning("重试发送 DATA block=%d (%d/%d)", block_num_mod, attempt, self.max_retries)
                            log_packet("重发", f"DATA block={block_num_mod}", data_pkt)

                        send_packet(self.sock, data_pkt, (self.server, self.server_ephemeral_port or self.port))

                        try:
                            data, peer = self.sock.recvfrom(65536)
                            opcode, ack_block, payload, err_msg = unpack_packet(data)
                        except socket.timeout:
                            logger.warning("等待 ACK(%d) 超时", block_num_mod)
                            continue

                        if peer[0] != self.server:
                            continue

                        if opcode == OP_ERROR:
                            raise TftpError(ack_block, err_msg or ERROR_NAMES.get(ack_block, "未知错误"))

                        if opcode == OP_ACK and ack_block == block_num_mod:
                            log_packet("接收", f"ACK block={ack_block}", data, peer)
                            retry_ok = True
                            break

                    if not retry_ok:
                        raise socket.timeout(f"发送 DATA block={block_num_mod} 失败（重试 {self.max_retries} 次）")

                    total_bytes += len(chunk)
                    block_count += 1
                    pct = total_bytes / file_size * 100 if file_size > 0 else 100
                    logger.info(
                        "  进度: block=%d, size=%d, total=%d bytes (%.1f%%)",
                        block_num_mod,
                        len(chunk),
                        total_bytes,
                        pct,
                    )

                    # 最后一个数据块（小于 blksize）
                    if len(chunk) < self.blksize:
                        logger.info("已发送最后一个数据块（size=%d < blocksize=%d）", len(chunk), self.blksize)
                        break

            elapsed = time.time() - start_time
            speed = total_bytes / elapsed if elapsed > 0 else 0
            logger.info("═" * 60)
            logger.info("上传完成 ✓")
            logger.info("  文件大小:  %d bytes (%.2f KB)", total_bytes, total_bytes / 1024)
            logger.info("  数据块:    %d", block_count)
            logger.info("  用时:      %.2fs", elapsed)
            speed_str = (
                f"{speed / 1024:.1f} KB/s" if speed < 1024 * 1024 else f"{speed / 1024 / 1024:.1f} MB/s"
            )
            logger.info("  速率:      %s", speed_str)
            logger.info("═" * 60)

        except TftpError as e:
            logger.error("服务器返回错误: %s", e)
            raise
        except socket.timeout:
            logger.error("传输超时")
            raise
        except KeyboardInterrupt:
            logger.warning("用户中断传输")
            raise
        finally:
            self.sock.close()


# ── CLI ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="TFTP 客户端模拟器 — 支持文件上传(put)和下载(get)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python tftp_client.py put 127.0.0.1 test.bin -v
  python tftp_client.py get 127.0.0.1 firmware.bin output.bin -v --blksize 1024
  python tftp_client.py put 192.168.1.1 config.cfg config.cfg -b 1468 -t 10
        """,
    )
    parser.add_argument(
        "command",
        choices=["put", "get"],
        help="操作类型: put=上传文件到服务器, get=从服务器下载文件",
    )
    parser.add_argument(
        "server",
        help="TFTP 服务器 IP 地址",
    )
    parser.add_argument("arg1", help="文件路径（put: 本地文件; get: 远程文件）")
    parser.add_argument(
        "arg2",
        nargs="?",
        default=None,
        help="第二个文件路径（put: 远程文件名, 默认同本地; get: 本地文件名, 默认同远程）",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=69,
        help="TFTP 服务端口（默认: 69）",
    )
    parser.add_argument(
        "-b",
        "--blksize",
        type=int,
        default=DEFAULT_BLKSIZE,
        help="数据块大小，字节（默认: 512）",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=5.0,
        help="单次接收超时，秒（默认: 5.0）",
    )
    parser.add_argument(
        "-r",
        "--retries",
        type=int,
        default=3,
        help="最大重试次数（默认: 3）",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="详细模式 — 输出所有数据包的 hex dump",
    )
    parser.add_argument(
        "--mode",
        choices=["octet", "netascii"],
        default="octet",
        help="传输模式（默认: octet）",
    )

    args = parser.parse_args()

    # 参数校验
    if args.blksize < 8 or args.blksize > 65464:
        print(f"错误: blksize 必须在 8..65464 之间，实际值: {args.blksize}", file=sys.stderr)
        sys.exit(1)

    # 配置日志
    _setup_logging(args.verbose)

    # 确定文件名
    if args.command == "put":
        local_file = args.arg1
        remote_file = args.arg2 or os.path.basename(local_file)
    else:  # get
        remote_file = args.arg1
        local_file = args.arg2 or os.path.basename(remote_file)

    # 创建客户端
    client = TftpClient(
        server=args.server,
        port=args.port,
        timeout=args.timeout,
        max_retries=args.retries,
        blksize=args.blksize,
        mode=args.mode,
    )

    try:
        if args.command == "put":
            client.send_file(local_file, remote_file)
        else:
            client.receive_file(remote_file, local_file)
    except FileNotFoundError as e:
        logger.error("%s", e)
        sys.exit(1)
    except PermissionError as e:
        logger.error("权限不足: %s", e)
        sys.exit(1)
    except TftpError as e:
        logger.error("TFTP 协议错误: %s", e)
        sys.exit(2)
    except socket.timeout as e:
        logger.error("传输超时: %s", e)
        sys.exit(3)
    except OSError as e:
        logger.error("网络/IO 错误: %s", e)
        sys.exit(4)
    except KeyboardInterrupt:
        print("\n传输已取消", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
