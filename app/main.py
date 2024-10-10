import json
import sys
from logging import ERROR
from sys import byteorder

import bencodepy
# import bencodepy - available if you need it!
# import requests - available if you need it!

# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"
import requests
import hashlib
import json

def hash_dict(d):
    def ensure_serializable(value):
        if isinstance(value, bytes):
            return value.decode('latin1')  # or use another encoding
        if isinstance(value, dict):
            return {k: ensure_serializable(v) for k, v in value.items()}
        if isinstance(value, list):
            return [ensure_serializable(v) for v in value]
        return value

    serializable_dict = ensure_serializable(d)
    json_str = json.dumps(serializable_dict, sort_keys=True)
    return hashlib.sha1(json_str.encode('utf-8')).hexdigest()

def decode_part(value, start_index):
    if chr(value[start_index]).isdigit():
        first_colon_index = value.find(b":")
        if first_colon_index == -1:
            raise ValueError("Invalid encoded value")
        return decode_string(value,start_index)
    elif chr(value[start_index]) == "i":
        return decode_integer(value,start_index)
    elif chr(value[start_index]) == "l":
        return decode_list(value,start_index)
    elif chr(value[start_index]) == "d":
        return decode_dict(value,start_index)
    else:
        raise NotImplementedError("Only strings are supported at the moment")



def decode_string(bencoded_value, start_index):
    if not chr(bencoded_value[start_index]).isdigit():
        raise ValueError("Invalid encoded string", bencoded_value, start_index)
    bencoded_value = bencoded_value[start_index:]
    first_colon_index = bencoded_value.find(b":")
    if first_colon_index == -1:
        raise ValueError("Invalid encoded value")
    length = int(bencoded_value[:first_colon_index])
    word_start = first_colon_index + 1
    word_end = first_colon_index + length + 1
    return bencoded_value[word_start:word_end], start_index + word_end


def decode_integer(bencoded_value, start_index):
    if chr(bencoded_value[start_index]) != "i":
        raise ValueError("Invalid encoded integer", bencoded_value, start_index)
    bencoded_value = bencoded_value[start_index:]
    end_marker = bencoded_value.find(b"e")
    if end_marker == -1:
        raise ValueError("Invalid encoded integer", bencoded_value)
    return int(bencoded_value[1:end_marker]), start_index + end_marker + 1

def decode_list(bencoded_value, start_index):
    if chr(bencoded_value[start_index]) != "l":
        raise ValueError("Invalid encoded list", bencoded_value, start_index)
    current_index = start_index + 1
    values = []
    while chr(bencoded_value[current_index]) != "e":
        value, current_index = decode_part(bencoded_value, current_index)
        values.append(value)
    return values, current_index + 1

def decode_dict(bencoded_value, start_index):
    if chr(bencoded_value[start_index]) != "d":
        raise ValueError("Invalid encoded dict", bencoded_value, start_index)
    current_index = start_index + 1
    values = {}
    while chr(bencoded_value[current_index]) != "e":
        key, current_index = decode_string(bencoded_value, current_index)
        value, current_index = decode_part(bencoded_value, current_index)
        values[key.decode()] = value
    return values, current_index

def decode_bencode(bencoded_value):
    return decode_part(bencoded_value, 0)[0]

def bencode_integer(value):
    return f"i{value}e".encode()
def bencode_string(value):
    return f"{len(value)}:{value}".encode()
def bencode_bytes(value):
    length = len(value)
    return str(length).encode() + b":" + value
def bencode_list(values):
    result = b"l"
    for value in values:
        result = result + bencode(value)
        result = result + b"e"

def bencode_dict(value):
    result = b"d"
    for key, value in value.items():
        result += bencode_string(key)
        result += bencode(value)
    result += b"e"
    return result

def bencode(value):
    if isinstance(value, int):
        return bencode_integer(value)
    elif isinstance(value, str):
        return bencode_string(value)
    elif isinstance(value, bytes):
        return bencode_bytes(value)
    elif isinstance(value, list):
        return bencode_list(value)
    elif isinstance(value, dict):
        return bencode_dict(value)
    else:
        raise ValueError("Unsupported type", value)

def httpget(url, params):
    response_content = requests.get(url,  params=params).content
    response = decode_bencode(response_content)
    return {json.dumps(response, indent=2)}
    # if response.status_code == 200:
    #     return response.json()
    # else:
    #     "failed to get url"
def main():
    command = sys.argv[1]

    # You can use print statements as follows for debugging, they'll be visible when running tests.
    # print("Logs from your program will appear here!")

    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        # json.dumps() can't handle bytes, but bencoded "strings" need to be
        # bytestrings since they might contain non utf-8 characters.
        #
        # Let's convert them to strings for printing to the console.
        def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()

            raise TypeError(f"Type not serializable: {type(data)}")

        # Uncomment this block to pass the first stage
        print(json.dumps(decode_bencode(bencoded_value), default=bytes_to_str))
    elif command == "info":
        file_name = sys.argv[2]
        with open(file_name, "rb") as torrent_file:
            bencoded_content = torrent_file.read()
        torrent = decode_bencode(bencoded_content)

        print("Tracker URL:", torrent["announce"].decode())
        print("Length:", torrent["info"]["length"])
        info_file = torrent["info"]
        bencoded_info_file = bencodepy.encode(info_file)
        sha1_hash = hashlib.sha1(bencoded_info_file).hexdigest()
        print("Info Hash:", sha1_hash)
        print("Piece Length:", torrent["info"]["piece length"])
        print("Piece Hashes:", torrent["info"]["pieces"].hex())
        print(info_file.keys())
        url = torrent["announce"].decode()
        query_params = dict(
            info_hash = sha1_hash,
            peer_id = "00112233445566778899",
            port = 6881,
            uploaded = 0,
            downloaded = 0,
            left = torrent["info"]["length"],
            compact = 1,
        )
        print(httpget(url, query_params))

    elif command == "peers":
        file_name = sys.argv[2]
        with open(file_name, "rb") as torrent_file:
            bencoded_content = torrent_file.read()
        torrent = decode_bencode(bencoded_content)
        url = torrent["announce"].decode()
        query_params = dict(
            info_hash=hashlib.sha1(bencode(torrent["info"])).digest(),
            peer_id="00112233445566778899",
            port=6881,
            uploaded=0,
            downloaded=0,
            left=torrent["info"]["length"],
            compact=1,
        )
        response = decode_bencode(requests.get(url, params=query_params).content)
        peers = response["peers"]
        for i in range(0, len(peers), 6):
            peer = peers[i: i + 6]
            ip_address = f"{peer[0]}.{peer[1]}.{peer[2]}.{peer[3]}"
            port = int.from_bytes(peer[4:], byteorder="big", signed=False)
            print(f"{ip_address}:{port}")
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
#koafkdsfkoasdfasfsaf