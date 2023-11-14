"""
Nayak Server
Note: This is just the underlying connection server. The actual Nayak protocol is implemented in the client.
"""

from flask import Flask, render_template
import socket
import threading
from datetime import datetime
import msgpack
import json
import os

# IAC Command Constants
IAC = 255
DONT = 254
DO = 253
WONT = 252
WILL = 251

# Common Telnet Option Constants
ECHO = 1
SUPPRESS_GO_AHEAD = 3

app = Flask(__name__)

SOCKET_PORT = 5011
HTTP_PORT = 5010

# Extended users dictionary format: {username: {'conn': connection, 'commands': [], 'messages_received': []}}
users = {}
server_metadata = {
    'server_name': 'Nayak Server',
    'server_version': '0.1',
    'server_description': 'The Nayak protocol server.',
    'server_author': 'Nayak Team',
    'server_author_email': 'nayak@fastmail.com',
    'server_website': 'https://meta.mn/nayak',
    'server_license': 'GPL v3',
    'server_license_url': 'https://www.gnu.org/licenses/gpl-3.0.en.html',
    'commercial_license': 'Contact us at nayak@fastmail.com for alternative commercial licensing.',
    'commercial_license_url': 'mailto:nayak@fastmail.com',
    'server_source': 'https://github.com/mindfulvector/Nayak-Server',
    'server_source_issue_tracker': 'https://github.com/mindfulvector/Nayak-Server/issues',
    'server_source_contributing': 'Contributions to this project are welcome. Please read the CONTRIBUTING.md file for more information, or type HELP CONTRIBUTING when connected to the server.',
    'server_source_contributors': [
        {'name': 'Mindful Vector', 'email': 'mv@fea.st'},
    ],
}

# Server ticks -- used for periodic tasks, incremented after every loop
# at all nesting levels. This may increment multiple times per second
# or not even once per second depending on server activity. It is likely
# to increase multiple times between and during process of each command
# received from each user.
#
# After hitting 65,565 (0xFFFF), it will wrap back to 0.
#
# Periodic tasks are run when the server ticks are divisible by a
# designated value.
server_ticks = 0

period_tasks = {}

checkpoint_filename = None

def main():
    global users, server_ticks, period_tasks, server_metadata, checkpoint_filename

    period_tasks['checkpoint'] = {
        'interval': 600, # ticks
        'last_run': -1,
        'function': checkpoint
    }

    checkpoint_filename = os.getcwd() + '/checkpoint.msgpack'

    threading.Thread(target=start_server).start()

    now = datetime.now()
    print(f'Starting Nayak Server on port {SOCKET_PORT} with HTTP port {HTTP_PORT} at {now}...')
    load_checkpoint()
    try:
        app.run(port=HTTP_PORT)
    except KeyboardInterrupt:
        now = datetime.now()
        printf(f'Shutting down Nayak Server at {now}...')
        checkpoint()

def user_is_connected(username):
    global users, server_ticks, period_tasks, server_metadata, checkpoint_filename
    if ('conn' in users[username]) and (None != users[username]['conn']) and (-1 != users[username]['conn'].fileno()):
        return True
    else:
        users[username]['conn'] = None
        return False

def server_tick():
    global users, server_ticks, period_tasks, server_metadata, checkpoint_filename
    server_ticks += 1

    for task, info in period_tasks.items():
        if (server_ticks % info['interval'] == 0):
            info['last_run'] = server_ticks
            info['function']()

def is_serializable(obj):
    try:
        msgpack.packb(obj)
        return True
    except msgpack.PackException as E:
        print(f'Cannot serialize object: {obj} - {type(obj)} - error: {E}')
        return False

def checkpoint():
    global users, server_ticks, period_tasks, server_metadata, checkpoint_filename
    
    # Notify connected users of checkpoint
    timestamp = datetime.now()

    print(f'[{timestamp}] Checkpoint to {checkpoint_filename}...');

    for recipient in users:
        if user_is_connected(recipient):
            users[recipient]['conn'].send(f'[{timestamp}] SYSTEM-MESSAGE: Checkpoint.\r\n'.encode('utf-8'))
    
    serializable_users = {}
    for user in users:
        serializable_user = {}
        for key, value in users[user].items():
            if 'conn' == key:
                continue
            if type(value) is datetime:
                serializable_user[key] = value.isoformat()
            else:
                if is_serializable(value):
                    serializable_user[key] = value
        serializable_users[user] = serializable_user
    
    #serializable_users = {username: {k: v for k, v in data.items() if k != 'conn'}
    #                      for username, data in users.items()}

    serializable_users_json = json.dumps(serializable_users)
    print(f'[{timestamp}] serializable_users: {serializable_users_json}')
    
    with open(checkpoint_filename, 'wb') as file:
        packed = msgpack.packb(serializable_users)
        file.write(packed)

    # Verify the file was written correctly
    with open(checkpoint_filename, 'rb') as file:
        packed = file.read()
        packed_users = msgpack.unpackb(packed)
        if packed_users:
            # Loop over live users list and check that each is stored properly in the packed DB
            for username, info in users.items():
                if username not in packed_users:
                    print(f'[{timestamp}] ERROR: Checkpoint failed. User `{username}` not found in packed DB.')
                else:
                    # Compare everything except the conn value which is transitory
                    for k in info:
                        try:
                            if info[k] != packed_users[username][k]:
                                print(f'[{timestamp}] ERROR: Checkpoint failed. User `{username}` {k} does not match.')
                        except KeyError:
                            if 'conn' != k:
                                print(f'[{timestamp}] ERROR: Checkpoint failed. User `{username}` {k} does not EXIST.')   


    print(f'[{timestamp}] Checkpoint complete.')

def load_checkpoint():
    global users, server_ticks, period_tasks, server_metadata, checkpoint_filename
    try:
        with open(checkpoint_filename, 'rb') as file:
            packed = file.read()
            users = msgpack.unpackb(packed)  # Unpack users data
    except FileNotFoundError:
        users = {}  # Initialize users if no checkpoint file is found

def generate_iac_packet(command, option):
    return bytes([IAC, command, option])

def handle_client(conn, username):
    global users, server_ticks, period_tasks, server_metadata, checkpoint_filename

    users[username]['last_active'] = datetime.now().isoformat()
    conn.send(f"\r\nUser {username} logged in.\r\n".encode('utf-8'))  # Login confirmation

    while True:
        server_tick()
        try:
            received_data = ""
            while not received_data.endswith("\n"):
                server_tick()
                raw_data = conn.recv(1024)
                if not raw_data:
                    break

                processed_data = bytearray()
                i = 0
                while i < len(raw_data):
                    server_tick()
                    if raw_data[i] == 0xff:  # IAC byte
                        # Handle the IAC sequence
                        # For simplicity, we'll just skip the next two bytes
                        # In a full implementation, you should properly parse the command
                        i += 3
                    else:
                        processed_data.append(raw_data[i])
                        i += 1

                # Now decode the remaining data as UTF-8
                data = processed_data.decode('utf-8')
                conn.send(data.encode('utf-8'))  # Echoing back the received data
                received_data += data

            data = None

            timestamp = datetime.now()
            users[username]['last_active'] = timestamp.isoformat()  # Update last active time

            command_parts = received_data.strip().split(' ')
            command = command_parts[0]

            if 'commands' not in users[username]:
                users[username]['commands'] = []

            # Tuples are deserialized as lists, which we must do because we need to be able to modify
            # other lists in the structure, so we need to not use tuples at all if we want the
            # structure to match when reloaded from disk
            users[username]['commands'].append([timestamp.isoformat(), received_data])

            if command == 'SEND':
                recipient = command_parts[1]
                message = ' '.join(command_parts[2:])       # Get remaining parts of the command as the message

                if recipient in users:
                    if user_is_connected(recipient):
                        users[recipient]['messages_received'].append({'timestamp': timestamp, 'message': message})
                        users[recipient]['conn'].send(f'[{timestamp}] {username}: {message}\r\n'.encode('utf-8'))
                        conn.send(f'OK: Message sent to {recipient}.\r\n'.encode('utf-8'))
                    else:
                        conn.send(f'ERROR: User `{recipient}` is not online.\r\n'.encode('utf-8'))
                else:
                    conn.send(f'ERROR: User `{recipient}` does not exist.\r\n'.encode('utf-8'))
            elif command == 'WHO':
                response = "Online users:\r\n"
                num = 0
                for user, info in users.items():
                    num += 1
                    response += f"#{num} - {user} - Last active: {info['last_active']}\r\n"
                conn.send(response.encode('utf-8'))
            elif command == 'HELP':
                if len(command_parts) > 1:
                    if command_parts[1] == 'CONTRIBUTING':
                        response = "Contributions to this project are welcome. Please read the CONTRIBUTING.md file for more information.\r\n"
                        response += "You can also visit the source code repository at: https://github.com/mindfulvector/Nayak-Server\r\n"
                        response += "If you have any questions, please contact us at nayak@fastmail.com\r\n"
                        conn.send(response.encode('utf-8'))
                    elif command_parts[1] == 'ABOUT':
                        response = json.dumps(server_metadata)
                        conn.send(response.encode('utf-8'))
                    else:
                        conn.send(f'ERROR: HELP topic not found. Some commands do not have additional documentation beyond the command definition in the HELP output. Type HELP for available commands and topics.\r\n'.encode('utf-8'))
                else:
                    response = "Available commands:\r\n"
                    response += "SEND <username> <message> - Send a message to a user\r\n"
                    response += "WHO - List all online users\r\n"
                    response += "HELP - Display this help message\r\n"
                    response += "HELP ABOUT - Display information about the server\r\n"
                    response += "QUIT - Disconnect from the server\r\n"
                    response += "TICKS - Display the current server tick count\r\n"
                    response += "TASKS - Display the current periodic tasks and their last run times\r\n"
                    conn.send(response.encode('utf-8'))
            elif command == 'TICKS':
                conn.send(f'OK: Server ticks: {server_ticks}\r\n'.encode('utf-8'))
            elif command == 'TASKS':
                response = "Periodic tasks:\r\n"
                for task, info in period_tasks.items():
                    response += f"{task} - Interval: {info['interval']}, Last run: {info['last_run']}\r\n"
                conn.send(response.encode('utf-8'))
            elif command == 'QUIT':
                users[username]['conn'] = None
                conn.send(f'OK: Goodbye.\r\n'.encode('utf-8'))
                conn.close()
                break
            elif command != '':
                conn.send(f'ERROR: Command was not understood. Type HELP for available commands.\r\n'.encode('utf-8'))

            # [Rest of the existing code]
        except Exception as e:
            print(f"Error: {e}")
            break

def start_server():
    global users

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', SOCKET_PORT))
    server.listen()

    while True:
        server_tick()
        conn, addr = server.accept()
        
        # Send WILL ECHO command to client
        conn.send(generate_iac_packet(WILL, ECHO))

        conn.send(f'Welcome to the {server_metadata["server_name"]}.\r\n'.encode('utf-8'))
        conn.send(f'Server license: {server_metadata["server_license"]}\r\n'.encode('utf-8'))
        conn.send(f'License URL: {server_metadata["server_license_url"]}\r\n'.encode('utf-8'))
        conn.send(f'Alternative commercial licensing: {server_metadata["commercial_license"]}\r\n'.encode('utf-8'))
        conn.send(f'Alternative commercial licensing URL: {server_metadata["commercial_license_url"]}\r\n'.encode('utf-8'))
        conn.send(f'\r\nPlease login with the LOGIN command.\r\n'.encode('utf-8'))

        # Wait for LOGIN command
        received_data = ""
        while not received_data.endswith("\n"):
            server_tick()
            raw_data = conn.recv(1024)
            if not raw_data:
                break

            processed_data = bytearray()
            i = 0
            while i < len(raw_data):
                server_tick()
                if raw_data[i] == 0xff:  # IAC byte
                    # Handle the IAC sequence
                    # For simplicity, we'll just skip the next two bytes
                    # In a full implementation, you should properly parse the command
                    i += 3
                else:
                    processed_data.append(raw_data[i])
                    i += 1

                # Now decode the remaining data as UTF-8
                data = processed_data.decode('utf-8')

                if not data:
                    break
                conn.send(data.encode('utf-8'))  # Echoing back the received data
                received_data += data

        data = None

        # Process received_data only if it's not empty and ends with a newline
        if received_data:
            received_data = received_data.strip()  # Removing the newline character
            cmd = received_data.split(' ')
            if (cmd[0] != 'LOGIN'):
                conn.send('ERROR: You must first login to the server. Bye.\r\n'.encode('utf-8'))
                conn.close()
                continue
            else:
                username = cmd[1]
                if (len(username) < 4):
                    conn.send('ERROR: Username must be at least 4 characters long. Bye.\r\n'.encode('utf-8'))
                    conn.close()
                    continue
                if username in users:       # Existing user
                    # Check if existing connection is still active
                    if not user_is_connected(username):
                        # Connection is inactive, update with new connection
                        users[username]['conn'] = conn
                    else:
                        # Connection is active, deny login
                        conn.send('ERROR: Username is already online. Bye.\r\n'.encode('utf-8'))
                        conn.close()
                        continue
                else:                       # New user
                    users[username] = {'conn': conn, 'commands': [], 'messages_received': [],
                               'first_login': datetime.now().isoformat(),
                               'last_active': datetime.now().isoformat()}
                    checkpoint()  # Save new user immediately
                thread = threading.Thread(target=handle_client, args=(conn, username))
                thread.start()


@app.route('/')
def index():
    return render_template('index.html', users=users)

if __name__ == '__main__':
    main()
