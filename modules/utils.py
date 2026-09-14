import os
import sys
import subprocess
import shutil
import logging
import urllib.parse
from datetime import datetime
from typing import Optional, List

class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    PURPLE = "\033[95m"

BANNER = r"""
 __      __                                      
/\ \  __/\ \                                      
\ \ \/\ \ \ \     __      ____  _____   __  __    
 \ \ \_/ \_\ \/\ \L\.\_\/__, `\ \ \L\ \ \ \_\ \  
  \ `\___x___/\ \__/.\_\/\____/\ \ ,__/\/`____ \ 
   '\/__//__/  \/__/\/_/\/___/  \ \ \/  `/___/> \
                                   \ \_\     /\___/
                                    \/_/     \/__/  
"""

def print_banner():
    print(f"{Colors.PURPLE}{Colors.BOLD}{BANNER.rstrip()}{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}    Waspy - Web Application Security Pentest Scanner{Colors.RESET}")
    print(f"{Colors.CYAN}    By Denilson França{Colors.RESET}")
    print(f"{Colors.YELLOW}    GitHub: https://github.com/Denilson-franca{Colors.RESET}")
    print(f"{Colors.BLUE}    LinkedIn: https://linkedin.com/in/denilson-franca{Colors.RESET}")
    print(f"{Colors.RED}{Colors.BOLD}{'='*70}{Colors.RESET}\n")

def color_log(msg: str, level: str = "INFO") -> None:
    colors = {
        "DEBUG": Colors.BLUE,
        "INFO": Colors.GREEN,
        "WARNING": Colors.YELLOW,
        "ERROR": Colors.RED,
        "CRITICAL": Colors.RED + Colors.BOLD,
    }
    prefix = f"[{datetime.now().strftime('%H:%M:%S')}] [{level}]"
    print(f"{colors.get(level, Colors.WHITE)}{prefix}{Colors.RESET} {msg}")

def setup_logger(verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger("waspy")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger

def run_command(command: List[str], timeout: int = 300, stealth: bool = False) -> Optional[subprocess.CompletedProcess]:
    """Run a command and return the completed process.

    When stealth=True, timeout is disabled (timeout=None) to allow slow
    rate-limited scans (e.g. Nuclei with -rate-limit 10) to finish.
    """
    actual_timeout = None if stealth else timeout
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=actual_timeout)
        return result
    except subprocess.TimeoutExpired:
        color_log(f"Command timed out: {' '.join(command)}", "ERROR")
        return None
    except FileNotFoundError:
        color_log(f"Command not found: {command[0]}", "ERROR")
        return None
    except Exception as e:
        color_log(f"Command failed: {' '.join(command)} - {e}", "ERROR")
        return None

def check_tool(name: str) -> bool:
    return shutil.which(name) is not None

def require_tool(name: str) -> bool:
    """Check if a tool is available, log warning if missing."""
    if not check_tool(name):
        color_log(f"Required tool '{name}' not found in PATH", "WARNING")
        return False
    return True

def validate_url(url: str) -> str:
    url = url.strip()
    if url.startswith("https://https://"):
        url = url.replace("https://https://", "https://")
    if url.startswith("http://http://"):
        url = url.replace("http://http://", "http://")
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    url = url.rstrip("/")
    parsed = urllib.parse.urlparse(url)
    if not parsed.netloc:
        raise ValueError(f"Invalid URL: {url}")
    return url
