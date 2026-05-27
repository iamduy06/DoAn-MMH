"""
ta_logger.py — Hệ thống ghi log cho Trusted Authority
Ghi lại: ai kết nối, xin key gì, lúc mấy giờ, kết quả
"""
import logging
import logging.handlers
import os
from datetime import datetime

# ──────────────────────────────────────────────────────────
# ANSI color codes cho console (chỉ dùng khi có terminal)
# ──────────────────────────────────────────────────────────
RESET   = "\033[0m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
RED     = "\033[91m"
CYAN    = "\033[96m"
BOLD    = "\033[1m"

class ColorFormatter(logging.Formatter):
    """Formatter có màu cho console."""
    COLORS = {
        logging.DEBUG:    CYAN,
        logging.INFO:     GREEN,
        logging.WARNING:  YELLOW,
        logging.ERROR:    RED,
        logging.CRITICAL: BOLD + RED,
    }

    def format(self, record):
        color = self.COLORS.get(record.levelno, RESET)
        record.levelname = f"{color}{record.levelname}{RESET}"
        return super().format(record)


def setup_logger(name: str = "TA_Server",
                 log_file: str = "logs/ta_server.log",
                 level: str = "INFO") -> logging.Logger:
    """
    Khởi tạo logger với 2 handler:
      - FileHandler  → ghi vào file (plain text)
      - StreamHandler → in ra console (có màu)
    """
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    logger.propagate = False

    if logger.handlers:          # tránh thêm handler trùng khi re-import
        return logger

    fmt_file    = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    fmt_console = f"{BOLD}%(asctime)s{RESET} | %(levelname)-18s | %(message)s"
    date_fmt    = "%Y-%m-%d %H:%M:%S"

    # ── File handler (rotating 5 MB × 5 backup) ──
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(logging.Formatter(fmt_file, datefmt=date_fmt))

    # ── Console handler ──
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(ColorFormatter(fmt_console, datefmt=date_fmt))

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger


# ──────────────────────────────────────────────────────────
# Hàm tiện ích: ghi log phiên hoạt động có cấu trúc
# ──────────────────────────────────────────────────────────
def log_session(logger: logging.Logger,
                event: str,
                client_addr: tuple,
                uid: str = "unknown",
                action: str = "",
                detail: str = "",
                success: bool = True):
    """
    Ghi một dòng log chuẩn cho một sự kiện phiên làm việc.

    Ví dụ output:
      [CONNECT ] 192.168.1.5:54321 | uid=doctor_001 | action=get_sk | attrs=['doctor','hospital_A'] | OK
    """
    status   = "OK" if success else "FAIL"
    ip, port = client_addr
    msg = (
        f"[{event:<8}] {ip}:{port} | uid={uid} | "
        f"action={action} | {detail} | {status}"
    )
    if success:
        logger.info(msg)
    else:
        logger.warning(msg)
