import os
import re
import struct
import asyncio
import asyncio_dgram
import aiofiles
import traceback
import argparse
from pydantic import BaseModel
from typing import Union, List
from aiohttp import web

class Address(BaseModel):
    addr: str
    port: int
    def __str__(self) -> str:
        return f"{self.addr}:{self.port}"

def unpack_byte(data: bytes):
    return struct.unpack('<B', data[:1])[0], data[1:]

def unpack_short(data: bytes):
    return struct.unpack('<h', data[:2])[0], data[2:]

def unpack_long(data: bytes):
    return struct.unpack('<l', data[:4])[0], data[4:]

def unpack_longlong(data: bytes):
    return struct.unpack('<Q', data[:8])[0], data[8:]

def unpack_float(data: bytes):
    return struct.unpack('<f', data[:4])[0], data[4:]

def unpack_string(data: bytes):
    return data.split(b'\x00', 1)

ms_list = [
    Address(**{"addr": "mentality.rip", "port": 27010}),
    Address(**{"addr": "mentality.rip", "port": 27011}),
    Address(**{"addr": "ms2.mentality.rip", "port": 27010})
    ]

async def send_packet(ip, port, msg, timeout: float) -> Union[bytes, None]:
    stream = await asyncio_dgram.connect((ip, port))
    await stream.send(msg)
    try:
        data, _ = await asyncio.wait_for(stream.recv(), timeout=timeout)
    except asyncio.TimeoutError:
        data = None
    finally:
        stream.close()

    return data

async def get_servers(gamedir:str, nat:bool, ms:Address, timeout:float) -> list[Address]:
    servers = []
    QUERY = b'1\xff0.0.0.0:0\x00\\nat\\%b\\gamedir\\%b\\clver\\0.21\x00' % (str(nat).encode(), gamedir.encode())

    data = await send_packet(ms.addr, ms.port, QUERY, timeout)

    if not data:
        return None

    data = data[6:]
    for i in range(0, len(data), 6):
        ip1, ip2, ip3, ip4, port = struct.unpack(b">BBBBH", data[i:i+6])
        servers.append(Address(addr=f"{ip1}.{ip2}.{ip3}.{ip4}", port=port))

    servers.pop()  # Last server is 0.0.0.0
    return servers

async def query_servers(target: Address, serverdict, timeout: float) -> None:
    queries = {
        48: b'\xff\xff\xff\xffinfo 48',
        49: b'\xff\xff\xff\xffinfo 49'
    }

    protocol = None
    raw = None

    for prot, query in queries.items():
        raw = await send_packet(target.addr, target.port, query, timeout)

        if raw is None or (b'wrong version' in raw and prot == 48):
            continue

        protocol = prot
        break

    if raw is None:
        return

    raw_str = raw.decode('utf-8', errors='ignore')
    sections = raw_str.split('\\')
    server_info = {sections[i]: sections[i + 1] for i in range(1, len(sections) - 1, 2)}


    for key in ["numcl", "maxcl", "dm", "team", "coop", "password"]:
        server_info[key] = int(server_info.get(key, 0))

    players_list = await get_players(target, timeout, protocol)

    server = {
        "addr": f"{target.addr}",
        "port": target.port,
        "host": server_info.get("host"),
        "map": server_info.get("map"),
        "numcl": server_info["numcl"],
        "maxcl": server_info["maxcl"],
        "gamedir": server_info.get("gamedir"),
        "dm": server_info["dm"],
        "team": server_info["team"],
        "coop": server_info["coop"],
        "password": server_info["password"],
        "protocol_ver": protocol,
        "players_list": players_list
    }

    serverdict["servers"].append(server.copy())

def draw_with_color_code(text):
    if text is None:
        return "None"

    color_code = {
        "^0": "color: #000000;",  # Black
        "^1": "color: #FF0000;",  # Red
        "^2": "color: #00FF00;",  # Green
        "^3": "color: #FFFF00;",  # Yellow
        "^4": "color: #0000FF;",  # Blue
        "^5": "color: #00FFFF;",  # Cyan
        "^6": "color: #FF00FF;",  # Magenta
        "^7": "color: #FFFFFF;",  # White
        "^8": "color: #000000;",  # Black (same as ^0)
        "^9": "color: #FF0000;"   # Red (again?)
    }

    def replace_color(match):
        code = match.group(0)
        return f'<span style="{color_code[code]}">' if code in color_code else code

    pattern = '|'.join(re.escape(code) for code in color_code.keys())
    modified_text = re.sub(pattern, replace_color, text)

    open_tags = modified_text.count('<span')
    close_tags = modified_text.count('</span')

    if open_tags > close_tags:
        modified_text += '</span>' * (open_tags - close_tags)

    return modified_text


def format_time(seconds):
    seconds = int(float(seconds))
    days = seconds // 86400
    hours = (seconds % 86400) // 3600
    minutes = (seconds % 3600) // 60
    remaining_seconds = seconds % 60

    time_components = []
    if days > 0:
        time_components.append(f"{days}d")
    if hours > 0:
        time_components.append(f"{hours}h")
    if minutes > 0:
        time_components.append(f"{minutes}m")
    if remaining_seconds > 0 or not time_components:
        time_components.append(f"{remaining_seconds}s")

    return ' '.join(time_components)

async def get_players(target: Address, timeout: float, protocol: int) -> dict:
    message = b'\xff\xff\xff\xff' + b'netinfo %b 0 3' % str(protocol).encode()

    data = await send_packet(target.addr, target.port, message, timeout)

    if not data:
        return {}

    data = data[16:]
    data = data.decode(errors='replace')
    data = "\\" + data.replace("'", ' ').replace('"', ' ').replace("'", ' ')
    data = data.split("\\")[1:]

    players_list = {}

    # Check protocol version
    if protocol == 49:
        if 'players' in data:
            num_players = int(data[data.index('players') + 1])

            for i in range(num_players):
                name = data[data.index(f"p{i}name") + 1]
                frags = data[data.index(f"p{i}frags") + 1]
                time = data[data.index(f"p{i}time") + 1]

                players_list[i] = [
                    name,
                    frags,
                    format_time(time)
                    ]
    else:
        for i in range(0, len(data), 4):
            if i + 3 < len(data):
                index = data[i]
                name = data[i + 1]
                frags = data[i + 2]
                time = data[i + 3]

                players_list[index] = [
                    name,
                    frags,
                    format_time(time)
                    ]

    return players_list

async def get_servers_status(request):
    gamedir = request.query.get('gamedir', None)

    if request.method == 'GET' and not gamedir:
        async with aiofiles.open('templates/select_gamedir.html', 'r') as file:
            return web.Response(text = await file.read(), content_type='text/html')

    elif gamedir:
        servers = {"servers": []}
        ip_list = await get_servers(gamedir, 0, ms_list[0], 0.5)

        if ip_list:
            coros = [query_servers(ip, servers, 0.5) for ip in ip_list]
            await asyncio.gather(*coros)

        if not servers["servers"]:
            async with aiofiles.open('templates/no_servers_found.html', 'r') as file:
                return web.Response(text = await file.read(), content_type='text/html')

        server_info_html = ""
        for i in servers['servers']:
            server_info_html += f"""
            <div class="server-info">
                <strong>Server:</strong> {draw_with_color_code(i['host'])}<br>
                <strong>Map:</strong> {i['map']} ({i['numcl']}/{i['maxcl']})<br>
            """
            if i['players_list']:
                player_entries = []
                for index, player_info in i['players_list'].items():
                    player_details = f"{draw_with_color_code(player_info[0])} [{player_info[1]}] ({player_info[2]})"
                    player_entries.append(f"{index} {player_details}")

                server_info_html += f"""
                <div class="player-list">
                    <strong># Name [kills] (Time)</strong><br>
                    {"<br>".join(player_entries)}<br>
                </div>
                """
            server_info_html += f"""
                <strong>IP:</strong> {i['addr']}:{i['port']}<br>
                <strong>Protocol:</strong> {i['protocol_ver']}, Xash3D FWGS {0.21 if i['protocol_ver'] == 49 else 0.19}<br>
            </div>
            """

        async with aiofiles.open('templates/available_servers.html', 'r') as file:
            template = await file.read()
            return web.Response(text = template.replace("{{ server_info|safe }}", server_info_html), content_type='text/html')

    return web.Response(text="Invalid request", status=400)

async def get_servers_api(request):
    gamedir = request.query.get('gamedir', None)

    servers = {"servers": []}
    ip_list = await get_servers(gamedir, 0, ms_list[0], 0.5)

    if ip_list:
        coros = [query_servers(ip, servers, 0.5) for ip in ip_list]
        await asyncio.gather(*coros)

    return web.json_response(servers)


app = web.Application()
app.router.add_static('/static/', path='static/', name='static')
app.router.add_get('/', get_servers_status)
app.router.add_get('/api/', get_servers_api)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run the web server.')
    parser.add_argument('-port', type=int, default=27100, help='Port to run the web server on (default: 27100)')
    args = parser.parse_args()
    web.run_app(app, port=args.port)
