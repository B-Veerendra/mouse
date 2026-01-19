# mouse


The project is a client-server system for remote control of Windows devices via a Telegram bot. The client part works in the background, connects to the server and executes commands, and the server part provides a convenient management interface via Telegram using topics. A separate topic is created for each client, which work independently of each other


Each client creates a separate topic in a forum group (like 🇷🇺 Win 10 | ⚡️ user | 94.141.124.208), just send commands to the appropriate topic to manage a specific client. The number of clients is conditionally unlimited. If the client, for example, closes the process, turns off the computer, or something else that eventually causes the connection to be interrupted (automatically restored if possible), you will receive notifications like “🔴 Client DESKTOP-MULMQ2N/... disconnected (OFFFLINE)!” If it connects successfully -“✅ DESKTOP-MULMQ2N/... online”. A timeout is also possible (similar to “offline”) “⏰ Timeout/Out of sync WIN-NB4GA5M6TVF/...”


📁 Project structure


✨ Full functionality
📁 File manager:
/ls [path] -list of files and folders (disks are shown at the root '/')
/cd <path> -change the current directory
/back -return to the parent folder (from the root of the disk goes to the list of disks)
/pwd -show current path
/mkdir <name> -create a folder
/delete <name> -delete a file or folder
/rename <old>/n<new> -rename a file or folder
/copy <source>/to<destination> -copy a file or folder
/move <source>/to<destination> -move a file or folder

📥 File transfer:
/download <file> -download a file from the client in Telegram
/upload [name] -upload a file from Telegram to the client (sent as a response to the file)
/download_link <URL> [0] -download the file from the link (0 -download without launching)

⚙️ System and command execution:
/run <file> -run a program or file
/execute <command> -execute a CMD or PowerShell command
/sysinfo -system information (CPU, memory, disk)
/tasklist -get a list of processes (sent as a TXT file)
/taskkill <name.exe or PID> -kill the process
/restart (unstable) -restart the client
/cmdbomb -open 10 CMD windows
/wd_exclude [path] -add the source or specified file to Windows Defender exceptions
/killwindef -temporarily disable Windows Defender
/grant <path> -gain full access to a folder or file (uses TakeOwn and Icacls)

💬 Interface and notifications:
/msg [type] [title]/t<text> -show a pop-up window on the client
/changeclipboard <text> -set the contents of the clipboard
/clipboard -get the contents of the clipboard
🖱️ Input and screen controls:
/screenshot or /sc -take a screenshot of the screen
/photo [index] -take a photo from the webcam
/minimize -minimize the active window
/maximize -maximize the active window
/altf4 -close the active window
/keypress <keys> -press a key combination (for example: alt f4, win r)
/holdkey <sec> <keys> -hold down a key or key combination for N seconds
/mouseclick -perform a mouse click
/mousemove <X> <Y> -move the mouse cursor to the specified coordinates
/keytype <text> -enter text with Cyrillic support
/open_image <sec> <path> -open the image full screen for N seconds
/applist [<index>] -view a list of windows or bring the selected window to the foreground
/applist_close <index> -close the selected window
/applist_title <index> <new name> -rename the selected window
/whereami -show the path to the current executable file

👾 Automation:
/mousemesstart -enable random mouse movement
/mousemesstop -stop random mouse movement
/auto <sec> [screen|webcam|both] [camera index] -auto-send screenshots or photos at a specified interval
/stop -stop executing the /auto command

🔇 Multimedia:
/playsound <path> -play an audio file on the client
/stopsound -stop audio playback
/mic <sec> – record sound from a microphone (up to 30 seconds)
/webcam <index> <sec> – record video from a webcam (up to 30 seconds)
/screenrecord <sec> – record video from the screen (up to 60 seconds)
/volumeplus [N] -increase volume (default +2%)
/volumeminus [N] -reduce volume (default -2%)

📎 Plugins:
/plugins_reload or /pl_upd -reload the list of plugins
/plugins -open the plugins control panel
/pl_on <ID> -enable the selected plugin
/pl_off <ID> -disable the selected plugin
/pl_rm <ID> -delete (from disk) the selected plugin
/install_lib <URL> -install the library via a direct link

🔧 Other commands:
/help -list of commands
/wallpaper <path> -set desktop wallpaper
/block -block mouse and keyboard
/unblock -unlock mouse and keyboard
/location — get the client’s location (country, city, IP, etc.)
/update [pastebin raw] -update the client software version
/clients — view the list of active clients and their history
/clients_off — list of inactive clients
/version -view the software version on the client side



🛠️ Additional features
Client

Automatic copying to the system folder, adding itself to the task scheduler
Deleting temporary files, closing junk process
Reconnection and heartbeat mechanisms
Unique device identification
Plugin support and disk encryption
Server

Asynchronous architecture: High performance
Multi-user: Supports multiple clients
Forum topics: Isolated chats for each device
Session history: Tracking client activity (online/offline)
🚀 Installation and configuration
Server part (Telegram bot)
You will need open ports, ideally a continuously working vds

Create a Telegram bot and get a token

Create a chat, enable “themes” in its settings (required), add the bot to the chat, give it administrator rights

Install the dependencies and next to the server.py file create data_info.txt with content like:

TOKEN = your token without quotes
GROUP_CHAT_ID = -123456789
Insert your token (without quotes) instead of "your token without quotes"

Instead of "-123456789" the ID (for example, -1002447758315) of your chat (one) where you just enabled topics. The bot cannot work in several chats at the same time(!)

Also in the server.py file itself, scroll down a little to the PORT variable, you can change the port if you need

The server can be started

Client part (Windows only)
There are a few changes that need to be made to the client.py file. In general, the code uses ("ideally") a configuration from pastebin like

{
   "ip": "121.43.65.121",
   "port": 7777
}
The port should be similar to that written on the server side, and the ip itself should also be the same as the server. The link to pastebin should be in the variable EXEC_URL = "https://pastebin.com/raw/xxxx"
It is also better to insert spare data into DEFAULT_IP, DEFAULT_PORT, they will be used if taking it from pastebin does not work. Or if you don’t want to make pastebin for tests, you can write an incorrect link, but normal alternative data, and after several unsuccessful attempts the client will automatically use the “default” ones

If you compile in exe, use the --uac-admin flag (or an alternative), since the code does not check for administrator rights

⚠️ Warning
This project was created for educational purposes. The author does not support the use of this software for illegal activities. Make sure that you have permission to manage the devices on which you are installing the client.
