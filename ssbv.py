import requests
import time
from ecdsa.numbertheory import inverse_mod
from hashlib import sha256
import os
from collections import defaultdict
from datetime import datetime
import signal
import sys
import math
import json
from ecdsa import SECP256k1, SigningKey, VerifyingKey
import binascii
import struct
import io

try:
    from Cryptodome.Hash import RIPEMD160
except ImportError:
    print("Warning: 'pycryptodome' library not found.")
    print("Please install it with: pip install pycryptodome")
    sys.exit(1)

class Colors:
    RESET = '\033[0m'
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    ORANGE = '\033[93m'
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'
    BRIGHT_ORANGE = '\033[93m'

    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'
    BG_ORANGE = '\033[93m'

    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    INVERT = '\033[7m'

# --- API Configuration ---
API_ORDER_TOTAL_TX = [
    "blockchain_info", "mempool", "blockstream", "sochain", "btc_com"
]

API_ORDER_RAW_HEX_FALLBACK = [
    ("blockchain_info", "/rawtx/{txid}?format=hex"),
    ("mempool", "/tx/{txid}/hex"),
    ("blockstream", "/tx/{txid}/hex"),
    ("blockstream", "/tx/{txid}"),
    ("sochain", "/get_tx/BTC/{txid}"),
    ("btc_com", "/tx/{txid}")
]

API_CONFIGS = {
    "blockchain_info": {
        "base_url": "https://blockchain.info",
        "total_tx_endpoint": "/address/{address}?format=json",
        "tx_list_endpoint": "/address/{address}?format=json&offset={offset}&limit={limit}",
        "raw_tx_endpoint_hex": "/rawtx/{txid}?format=hex",
        "parser": {
            "total_tx": lambda data: data.get('n_tx', 0),
            "transactions_from_list": lambda data: [tx.get('hash') for tx in data.get('txs', []) if tx.get('hash')],
            "get_raw_hex_from_plain_response": lambda response_text: response_text.strip()
        }
    },
    "mempool": {
        "base_url": "https://mempool.space/api",
        "total_tx_endpoint": "/address/{address}",
        "tx_list_endpoint": "/address/{address}/txs",
        "raw_tx_endpoint_hex": "/tx/{txid}/hex",
        "parser": {
            "total_tx": lambda data: data.get('chain_stats', {}).get('tx_count', 0),
            "transactions_from_list": lambda data: [tx.get('txid') for tx in data if tx.get('txid')],
            "get_raw_hex_from_plain_response": lambda response_text: response_text
        }
    },
    "blockstream": {
        "base_url": "https://blockstream.info/api",
        "total_tx_endpoint": "/address/{address}",
        "tx_list_endpoint": "/address/{address}/txs",
        "raw_tx_endpoint_hex": "/tx/{txid}/hex",
        "raw_tx_endpoint_json": "/tx/{txid}",
        "parser": {
            "total_tx": lambda data: data.get('chain_stats', {}).get('tx_count', 0),
            "transactions_from_list": lambda data: [tx.get('txid') for tx in data if tx.get('txid')],
            "get_raw_hex_from_plain_response": lambda response_text: response_text,
            "get_raw_hex_from_json_response": lambda data: data.get('hex', None)
        }
    },
    "sochain": {
        "base_url": "https://sochain.com/api/v2",
        "total_tx_endpoint": "/address/BTC/{address}",
        "tx_list_endpoint": "/address/BTC/{address}",
        "raw_tx_endpoint_json": "/get_tx/BTC/{txid}",
        "parser": {
            "total_tx": lambda data: data.get('data', {}).get('txs', []).__len__(),
            "transactions_from_list": lambda data: [tx.get('txid') for tx in data.get('data', {}).get('txs', []) if tx.get('txid')],
            "get_raw_hex_from_json_response": lambda data: data.get('data', {}).get('tx_hex', None)
        }
    },
    "btc_com": {
        "base_url": "https://chain.api.btc.com/v3",
        "total_tx_endpoint": "/address/{address}",
        "tx_list_endpoint": "/address/{address}/tx?offset={offset}&limit={limit}",
        "raw_tx_endpoint_json": "/tx/{txid}",
        "parser": {
            "total_tx": lambda data: data.get('data', {}).get('total_tx', 0),
            "transactions_from_list": lambda data: [tx.get('hash') for tx in data.get('data', {}).get('list', []) if tx.get('hash')],
            "get_raw_hex_from_json_response": lambda data: data.get('data', {}).get('hex', None)
        }
    }
}

# Global variables for reporting
TOTAL_ADDRESSES = 0
SCANNED_ADDRESSES = 0
VULNERABLE_ADDRESSES = 0
VULN_COUNTS = defaultdict(int)
CURRENT_ADDRESS = ""
SCANNED_ADDRESS_LIST = []
MAX_DISPLAYED_ADDRESSES = 10
EXIT_FLAG = False
REPORTS = []
MAX_TRANSACTIONS = 0
GLOBAL_MAX_SMALL_K_ATTEMPT = 0

# Configurable delay between API calls (in seconds)
SCAN_DELAY_SECONDS = 0.5

# Constants for SECP256k1
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = SECP256k1.order
G = SECP256k1.generator

S_MAX_HALF = N // 2 

_BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# Bitcoin Script Opcodes (Relevant for parsing)
OP_DUP = 0x76
OP_HASH160 = 0xA9
OP_EQUALVERIFY = 0x88
OP_CHECKSIG = 0xAC
OP_EQUAL = 0x87
OP_CHECKMULTISIG = 0xAE
OP_0 = 0x00
OP_1 = 0x51
OP_2 = 0x52
OP_3 = 0x53
OP_4 = 0x54
OP_5 = 0x55
OP_6 = 0x56
OP_7 = 0x57
OP_8 = 0x58
OP_9 = 0x59
OP_10 = 0x5a
OP_11 = 0x5b
OP_12 = 0x5c
OP_13 = 0x5d
OP_14 = 0x5e
OP_15 = 0x5f
OP_16 = 0x60

# Map OP_N to integer N
OP_N_MAPPING = {
    OP_0: 0, OP_1: 1, OP_2: 2, OP_3: 3, OP_4: 4, OP_5: 5, OP_6: 6, OP_7: 7, OP_8: 8,
    OP_9: 9, OP_10: 10, OP_11: 11, OP_12: 12, OP_13: 13, OP_14: 14, OP_15: 15, OP_16: 16
}

# Nonce Bias Threshold
NONCE_BIAS_THRESHOLD = 2

# Cache for fetched raw transaction hexes
TX_RAW_HEX_CACHE = {}

# --- Utility Functions ---

def signal_handler(sig, frame):
    global EXIT_FLAG
    print(f"\n{Colors.YELLOW}Signal {sig} received. Preparing to stop scanning.{Colors.RESET}")
    EXIT_FLAG = True

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def hex_to_int(h):
    return int(h, 16)

def int_to_hex(i):
    return hex(i)

def hash160(public_key_bytes):
    ripemd160 = RIPEMD160.new()
    ripemd160.update(sha256(public_key_bytes).digest())
    return ripemd160.digest()

def encode_base58(v):
    base58_string = b""
    x = int.from_bytes(v, 'big')
    while x > 0:
        x, mod = divmod(x, 58)
        base58_string = _BASE58_ALPHABET[mod:mod+1] + base58_string

    for byte in v:
        if byte == 0x00:
            base58_string = b"1" + base58_string
        else:
            break
    return base58_string.decode('utf-8')

def point_to_pubkey_bytes(point, compressed=True):
    if compressed:
        prefix = b'\x02' if point.y() % 2 == 0 else b'\x03'
        return prefix + point.x().to_bytes(32, byteorder='big')
    else:
        return b'\x04' + point.x().to_bytes(32, byteorder='big') + point.y().to_bytes(32, byteorder='big')

def public_key_to_address(public_key_hex, is_compressed=True, script_type='P2PKH'):
    try:
        public_key_bytes = binascii.unhexlify(public_key_hex)
        
        if script_type == 'P2PKH':
            if is_compressed:
                vh160 = b'\x00' + hash160(public_key_bytes)
            else:
                vh160 = b'\x00' + hash160(public_key_bytes)
            
            checksum = sha256(sha256(vh160).digest()).digest()[:4]
            address = encode_base58(vh160 + checksum)
            return address
        elif script_type == 'P2WPKH':
            return "P2WPKH_Address_Requires_Bech32_Encoding"
        elif script_type == 'P2SH-P2WPKH':
            redeem_script = b'\x00\x14' + hash160(public_key_bytes)
            script_hash = hash160(redeem_script)
            vh160 = b'\x05' + script_hash
            checksum = sha256(sha256(vh160).digest()).digest()[:4]
            address = encode_base58(vh160 + checksum)
            return address
        else:
            return "Unsupported_Script_Type"
    except Exception as e:
        return "Invalid_Pubkey_Address_Conversion_Error"

def display_stats():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"{Colors.BRIGHT_CYAN}{'='*80}{Colors.RESET}")
    print(f"{Colors.BRIGHT_BLUE}🔍 Signature Scanner for Bitcoin Vulnerability{Colors.RESET}")
    print(f"{Colors.BRIGHT_BLACK}📅 Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
    print(f"{Colors.BRIGHT_BLUE}🔧 SecAnalysts @2025 | Ctrl+C to stop scan{Colors.RESET}")
    print(f"{Colors.BRIGHT_BLUE}💰 DONATE BITCOIN :1sAXERLyPhg4Fg4rkhuRQfm9eek2NJo6V{Colors.RESET}")
    print(f"{Colors.BRIGHT_CYAN}{'='*80}{Colors.RESET}")
    print(f"{Colors.BRIGHT_WHITE}📊 Progress Statistics:{Colors.RESET}")
    print(f"  {Colors.WHITE}• Total Addresses:{Colors.RESET} {Colors.YELLOW}{TOTAL_ADDRESSES}{Colors.RESET}")
    print(f"  {Colors.WHITE}• Remaining Addresses:{Colors.RESET} {Colors.YELLOW}{TOTAL_ADDRESSES - SCANNED_ADDRESSES}{Colors.RESET}")
    print(f"  {Colors.WHITE}• Scanned Addresses:{Colors.RESET} {Colors.CYAN}{SCANNED_ADDRESSES}{Colors.RESET}")
    percentage = (VULNERABLE_ADDRESSES/SCANNED_ADDRESSES*100) if SCANNED_ADDRESSES > 0 else 0
    vuln_color = Colors.GREEN if percentage == 0 else Colors.YELLOW if percentage < 10 else Colors.RED
    print(f"  {Colors.WHITE}• Vulnerable Addresses:{Colors.RESET} {vuln_color}{VULNERABLE_ADDRESSES} ({percentage:.1f}%){Colors.RESET}")
    print(f"{Colors.BRIGHT_CYAN}{'='*80}{Colors.RESET}")

    # Perfectly aligned vulnerability table
    print(f"\n{Colors.BRIGHT_WHITE}🚨 Vulnerability Summary:{Colors.RESET}")
    
    # Define column widths and styles
    SEV_WIDTH = 14
    VULN_WIDTH = 38
    COUNT_WIDTH = 8
    BORDER = Colors.BRIGHT_CYAN
    HEADER = Colors.BRIGHT_WHITE
    RESET = Colors.RESET
    
    # Table header
    print(f"{BORDER}╔{'═'*SEV_WIDTH}╦{'═'*VULN_WIDTH}╦{'═'*COUNT_WIDTH}╗{RESET}")
    print(f"{BORDER}║{HEADER}{'Severity'.center(SEV_WIDTH)}{BORDER}║{HEADER}{'Vulnerability'.center(VULN_WIDTH)}{BORDER}║{HEADER}{'Count'.center(COUNT_WIDTH)}{BORDER}║{RESET}")
    print(f"{BORDER}╠{'═'*SEV_WIDTH}╬{'═'*VULN_WIDTH}╬{'═'*COUNT_WIDTH}╣{RESET}")

    # Helper function to print table rows
    def print_row(severity, severity_color, vuln_name, vuln_color, count):
        severity_text = f"{severity_color}{severity.ljust(SEV_WIDTH-2)}{RESET}"
        vuln_text = f"{vuln_color}{vuln_name.ljust(VULN_WIDTH-2)}{RESET}"
        count_text = f"{vuln_color}{str(count).rjust(COUNT_WIDTH-2)}{RESET}"
        print(f"{BORDER}║ {severity_text}{BORDER} ║ {vuln_text}{BORDER} ║ {count_text}{BORDER} ║{RESET}")

    # High severity vulnerabilities
    print_row("HIGH", Colors.BRIGHT_RED, "Reused Nonce", Colors.RED, VULN_COUNTS['Reused Nonce'])
    print_row("", "", "Multi-Nonce Delta", Colors.RED, VULN_COUNTS['Multi-Nonce Delta'])
    print_row("", "", "Guessable Small K-Value", Colors.RED, VULN_COUNTS['Guessable Small K-Value'])
    print_row("", "", "Fault Attack", Colors.RED, VULN_COUNTS['Fault Attack'])
    print(f"{BORDER}╠{'─'*SEV_WIDTH}╬{'─'*VULN_WIDTH}╬{'─'*COUNT_WIDTH}╣{RESET}")

    # Medium severity vulnerabilities
    print_row("MEDIUM", Colors.ORANGE, "LLL Attack (Bias S/R)", Colors.ORANGE, VULN_COUNTS['LLL Attack (Bias S/R)'])
    print_row("", "", "Low Order Points", Colors.ORANGE, VULN_COUNTS['Low Order Points'])
    print(f"{BORDER}╠{'─'*SEV_WIDTH}╬{'─'*VULN_WIDTH}╬{'─'*COUNT_WIDTH}╣{RESET}")

    # Low severity vulnerabilities
    print_row("LOW", Colors.YELLOW, "Nonce Bias (Small R)", Colors.YELLOW, VULN_COUNTS['Nonce Bias (Small R)'])
    print_row("", "", "Nonce Bias (Leading Zeros S/R)", Colors.YELLOW, 
             VULN_COUNTS['Nonce Bias (Leading Zeros in R)'] + VULN_COUNTS['Nonce Bias (Leading Zeros in S)'])
    print(f"{BORDER}╠{'─'*SEV_WIDTH}╬{'─'*VULN_WIDTH}╬{'─'*COUNT_WIDTH}╣{RESET}")

    # Informational vulnerabilities
    print_row("INFORMATIVE", Colors.GREEN, "Non-Canonical Signature", Colors.GREEN, VULN_COUNTS['Non-Canonical Signature'])
    print_row("", "", "Weak RNG Indicators", Colors.GREEN, 
             VULN_COUNTS['Weak RNG'] + VULN_COUNTS['Weak RNG (Statistical)'])

    # Table footer
    print(f"{BORDER}╚{'═'*SEV_WIDTH}╩{'═'*VULN_WIDTH}╩{'═'*COUNT_WIDTH}╝{RESET}")

    # Current scan info
    print(f"\n{Colors.BRIGHT_WHITE}🔍 Currently Scanning:{Colors.RESET}")
    print(f"  {Colors.BRIGHT_MAGENTA}{CURRENT_ADDRESS}{Colors.RESET}")

    # Recent vulnerable addresses
    print(f"\n{Colors.BRIGHT_WHITE}⚠️ Recent Vulnerable Addresses:{Colors.RESET}")
    vulnerable_addrs = [report['address'] for report in REPORTS if report['vulnerabilities']]
    start_idx = max(0, len(vulnerable_addrs) - MAX_DISPLAYED_ADDRESSES)
    if not vulnerable_addrs:
        print(f"  {Colors.GREEN}No vulnerabilities found yet{Colors.RESET}")
    else:
        for addr in vulnerable_addrs[start_idx:]:
            print(f"  {Colors.RED}➜ {addr}{Colors.RESET}")
    
    print(f"{Colors.BRIGHT_CYAN}{'='*80}{Colors.RESET}")
    
def _make_api_request_with_retries(url, retries=5, timeout=15, api_name="Unknown API", method="GET"):
    sleep_time = 10 
    for i in range(retries):
        try:
            response = requests.request(method, url, timeout=timeout)
            response.raise_for_status()

            try:
                return response.json()
            except json.JSONDecodeError:
                return response.text.strip()

        except requests.exceptions.HTTPError as e:
            if "0000000000000000000000000000000000000000000000000000000000000000" in url:
                return None
            
            print(f"{Colors.RED}HTTP Error {e.response.status_code} from {api_name} for {url}. Waiting {sleep_time} seconds before retrying (attempt {i+1}/{retries})...{Colors.RESET}")
            time.sleep(sleep_time)
            sleep_time = min(sleep_time * 2, 60)
        except requests.exceptions.Timeout as e:
            print(f"{Colors.RED}Timeout error from {api_name} for {url}: {e}. Waiting {sleep_time} seconds before retrying (attempt {i+1}/{retries})...{Colors.RESET}")
            time.sleep(sleep_time)
        except requests.exceptions.ConnectionError as e:
            print(f"{Colors.RED}Connection error from {api_name} for {url}: {e}. Waiting {sleep_time} seconds before retrying (attempt {i+1}/{retries})...{Colors.RESET}")
            time.sleep(sleep_time)
        except requests.exceptions.RequestException as e:
            print(f"{Colors.RED}General RequestException from {api_name} for {url}: {e}. Waiting {sleep_time} seconds before retrying (attempt {i+1}/{retries})...{Colors.RESET}")
            time.sleep(sleep_time)
        
        if EXIT_FLAG:
            return None
    print(f"{Colors.BRIGHT_RED}Failed to get data from {api_name} for {url} after {retries} attempts.{Colors.RESET}")
    return None

def get_total_transactions(address):
    for api_name in API_ORDER_TOTAL_TX:
        api_conf = API_CONFIGS[api_name]
        url = api_conf["base_url"] + api_conf["total_tx_endpoint"].format(address=address)
        print(f"{Colors.BLUE}Attempting to get total transactions from {api_name} for {address}...{Colors.RESET}")
        data = _make_api_request_with_retries(url, api_name=api_name)
        if data:
            try:
                if 'total_tx' in api_conf['parser']:
                    total_tx = api_conf['parser']['total_tx'](data)
                else:
                    total_tx = None

                if total_tx is not None:
                    print(f"{Colors.GREEN}Successfully got total transactions from {api_name}: {total_tx}{Colors.RESET}")
                    return total_tx, api_conf
            except Exception as e:
                print(f"{Colors.YELLOW}Warning: Error parsing total transactions from {api_name}: {e}. Trying next API.{Colors.RESET}")
        
        print(f"{Colors.YELLOW}Failed to get total transactions from {api_name}. Trying next API.{Colors.RESET}")
        if EXIT_FLAG: break
    
    print(f"{Colors.BRIGHT_RED}Failed to get total transactions from all configured APIs.{Colors.RESET}")
    return 0, None

def get_raw_hex_for_txid(txid):
    if txid in TX_RAW_HEX_CACHE:
        return TX_RAW_HEX_CACHE[txid]

    for api_name, endpoint_path in API_ORDER_RAW_HEX_FALLBACK:
        api_conf = API_CONFIGS.get(api_name)
        if not api_conf:
            print(f"{Colors.YELLOW}Warning: API configuration not found for {api_name}. Skipping.{Colors.RESET}")
            continue

        url = api_conf["base_url"] + endpoint_path.format(txid=txid)

        response_data = _make_api_request_with_retries(url, api_name=api_name)
        
        if response_data:
            raw_hex = None
            try:
                if endpoint_path.endswith('/hex') and 'get_raw_hex_from_plain_response' in api_conf['parser']:
                    raw_hex = api_conf['parser']['get_raw_hex_from_plain_response'](response_data)
                elif 'get_raw_hex_from_json_response' in api_conf['parser']:
                    raw_hex = api_conf['parser']['get_raw_hex_from_json_response'](response_data)
                
                if raw_hex and raw_hex.strip():
                    TX_RAW_HEX_CACHE[txid] = raw_hex.strip()
                    return raw_hex.strip()
            except Exception as e:
                print(f"{Colors.YELLOW}Warning: Error parsing raw hex from {api_name} ({endpoint_path}) for {txid}: {e}. Trying next fallback API.{Colors.RESET}")
        
        if EXIT_FLAG: return None

    return None

def read_varint(f):
    first_byte = f.read(1)[0]
    if first_byte < 0xfd:
        return first_byte
    if first_byte == 0xfd:
        return struct.unpack('<H', f.read(2))[0]
    if first_byte == 0xfe:
        return struct.unpack('<I', f.read(4))[0]
    return struct.unpack('<Q', f.read(8))[0]

def write_varint(f, i):
    if i < 0xfd:
        f.write(struct.pack('<B', i))
    elif i <= 0xffff:
        f.write(b'\xfd' + struct.pack('<H', i))
    elif i <= 0xffffffff:
        f.write(b'\xfe' + struct.pack('<I', i))
    else:
        f.write(b'\xff' + struct.pack('<Q', i))

def parse_script(f):
    script_len = read_varint(f)
    return f.read(script_len)

def serialize_script(f, script_bytes):
    write_varint(f, len(script_bytes))
    f.write(script_bytes)

def parse_tx_in_raw(f):
    prev_tx_id = f.read(32)[::-1]
    output_idx = struct.unpack('<I', f.read(4))[0]
    script_sig = parse_script(f)
    sequence = struct.unpack('<I', f.read(4))[0]
    return {
        'prev_tx_id_bytes': prev_tx_id,
        'output_idx': output_idx,
        'script_sig_bytes': script_sig,
        'sequence': sequence
    }

def parse_tx_out_raw(f):
    value = struct.unpack('<Q', f.read(8))[0]
    script_pubkey = parse_script(f)
    return {
        'value': value,
        'script_pubkey_bytes': script_pubkey
    }

def parse_raw_transaction_internal(raw_tx_hex):
    f = io.BytesIO(binascii.unhexlify(raw_tx_hex))
    
    tx = {}
    tx['version'] = struct.unpack('<I', f.read(4))[0]
    
    peek_byte = f.read(1)[0]
    is_segwit = False
    if peek_byte == 0x00:
        flag = f.read(1)[0]
        if flag == 0x01:
            is_segwit = True
            tx['marker'] = 0x00
            tx['flag'] = 0x01
        else:
            f.seek(-2, io.SEEK_CUR)
    else:
        f.seek(-1, io.SEEK_CUR)

    num_inputs = read_varint(f)
    tx['inputs'] = []
    for _ in range(num_inputs):
        tx['inputs'].append(parse_tx_in_raw(f))
        
    num_outputs = read_varint(f)
    tx['outputs'] = []
    for _ in range(num_outputs):
        tx['outputs'].append(parse_tx_out_raw(f))
        
    if is_segwit:
        tx['witnesses'] = []
        for _ in range(num_inputs):
            num_witness_items = read_varint(f)
            witness_items = []
            for _ in range(num_witness_items):
                item_len = read_varint(f)
                witness_items.append(f.read(item_len))
            tx['witnesses'].append(witness_items)

    tx['locktime'] = struct.unpack('<I', f.read(4))[0]
    
    return tx, is_segwit

def get_utxo_details_for_sighash(prev_tx_id_hex, output_idx):
    raw_hex = get_raw_hex_for_txid(prev_tx_id_hex)
    if not raw_hex:
        return None, None

    try:
        parsed_prev_tx, _ = parse_raw_transaction_internal(raw_hex)
        
        if output_idx >= len(parsed_prev_tx['outputs']):
            print(f"{Colors.YELLOW}Warning: Output index {output_idx} out of bounds for prev_tx {prev_tx_id_hex}.{Colors.RESET}")
            return None, None

        spent_output = parsed_prev_tx['outputs'][output_idx]
        return spent_output['script_pubkey_bytes'], spent_output['value']
    except Exception as e:
        print(f"{Colors.RED}Error parsing prev_tx {prev_tx_id_hex} or getting UTXO details: {e}.{Colors.RESET}")
        return None, None

def get_sighash_z(parsed_tx_internal, input_index, script_code_bytes, spent_utxo_value, sighash_type_byte, is_segwit_v0):
    SIGHASH_ALL = 0x01
    SIGHASH_NONE = 0x02
    SIGHASH_SINGLE = 0x03
    SIGHASH_ANYONECANPAY = 0x80

    hash_type = sighash_type_byte & 0x1f
    is_anyone_can_pay = (sighash_type_byte & SIGHASH_ANYONECANPAY) != 0

    s_preimage = io.BytesIO()

    s_preimage.write(struct.pack('<I', parsed_tx_internal['version']))

    if is_segwit_v0:
        if not is_anyone_can_pay:
            hash_prevouts = sha256(sha256(b''.join([
                tx_in['prev_tx_id_bytes'] + struct.pack('<I', tx_in['output_idx'])
                for tx_in in parsed_tx_internal['inputs']
            ])).digest()).digest()
            s_preimage.write(hash_prevouts)
        else:
            s_preimage.write(b'\x00' * 32)

        if not is_anyone_can_pay and hash_type != SIGHASH_SINGLE and hash_type != SIGHASH_NONE:
            hash_sequence = sha256(sha256(b''.join([
                struct.pack('<I', tx_in['sequence'])
                for tx_in in parsed_tx_internal['inputs']
            ])).digest()).digest()
            s_preimage.write(hash_sequence)
        else:
            s_preimage.write(b'\x00' * 32)
    
    current_input = parsed_tx_internal['inputs'][input_index]
    s_preimage.write(current_input['prev_tx_id_bytes'])
    s_preimage.write(struct.pack('<I', current_input['output_idx']))

    serialize_script(s_preimage, script_code_bytes)

    if is_segwit_v0:
        s_preimage.write(struct.pack('<Q', spent_utxo_value))

    s_preimage.write(struct.pack('<I', current_input['sequence']))

    if hash_type == SIGHASH_ALL:
        outputs_stream = io.BytesIO()
        for tx_out in parsed_tx_internal['outputs']:
            outputs_stream.write(struct.pack('<Q', tx_out['value']))
            serialize_script(outputs_stream, tx_out['script_pubkey_bytes'])
        hash_outputs = sha256(sha256(outputs_stream.getvalue()).digest()).digest()
        s_preimage.write(hash_outputs)
    elif hash_type == SIGHASH_SINGLE:
        if input_index < len(parsed_tx_internal['outputs']):
            single_output = parsed_tx_internal['outputs'][input_index]
            outputs_stream = io.BytesIO()
            outputs_stream.write(struct.pack('<Q', single_output['value']))
            serialize_script(outputs_stream, single_output['script_pubkey_bytes'])
            hash_outputs = sha256(sha256(outputs_stream.getvalue()).digest()).digest()
            s_preimage.write(hash_outputs)
        else:
            s_preimage.write(b'\x00' * 32)
    else:
        s_preimage.write(b'\x00' * 32)

    s_preimage.write(struct.pack('<I', parsed_tx_internal['locktime']))

    s_preimage.write(struct.pack('<I', sighash_type_byte))
    
    return int.from_bytes(sha256(sha256(s_preimage.getvalue()).digest()).digest(), 'big')

def parse_der_signature(der_sig_hex):
    try:
        der_sig_bytes = bytes.fromhex(der_sig_hex)
        
        if not der_sig_bytes.startswith(b'\x30'):
            return None, None

        total_len_byte = der_sig_bytes[1]
        if total_len_byte & 0x80:
            num_len_bytes = total_len_byte & 0x7f
            if len(der_sig_bytes) < 2 + num_len_bytes:
                return None, None
            total_len = int.from_bytes(der_sig_bytes[2 : 2 + num_len_bytes], 'big')
            offset = 2 + num_len_bytes
        else:
            total_len = total_len_byte
            offset = 2

        if len(der_sig_bytes) != total_len + offset:
            return None, None

        if len(der_sig_bytes) < offset + 2 or der_sig_bytes[offset] != 0x02:
            return None, None
        r_len_byte = der_sig_bytes[offset + 1]
        if r_len_byte & 0x80:
            num_r_len_bytes = r_len_byte & 0x7f
            if len(der_sig_bytes) < offset + 2 + num_r_len_bytes:
                return None, None
            r_len = int.from_bytes(der_sig_bytes[offset + 2 : offset + 2 + num_r_len_bytes], 'big')
            r_start = offset + 2 + num_r_len_bytes
        else:
            r_len = r_len_byte
            r_start = offset + 2
        
        r_end = r_start + r_len
        if len(der_sig_bytes) < r_end:
            return None, None
        r = int.from_bytes(der_sig_bytes[r_start:r_end], 'big')

        s_offset = r_end
        if len(der_sig_bytes) < s_offset + 2 or der_sig_bytes[s_offset] != 0x02:
            return None, None
        s_len_byte = der_sig_bytes[s_offset + 1]
        if s_len_byte & 0x80:
            num_s_len_bytes = s_len_byte & 0x7f
            if len(der_sig_bytes) < s_offset + 2 + num_s_len_bytes:
            
                return None, None
            s_len = int.from_bytes(der_sig_bytes[s_offset + 2 : s_offset + 2 + num_s_len_bytes], 'big')
            s_start = s_offset + 2 + num_s_len_bytes
        else:
            s_len = s_len_byte
            s_start = s_offset + 2

        s_end = s_start + s_len
        if len(der_sig_bytes) < s_end:
            return None, None
        s = int.from_bytes(der_sig_bytes[s_start:s_end], 'big')

        return r, s
    except Exception as e:
        return None, None

def decode_script(script_hex):
    try:
        script_bytes = bytes.fromhex(script_hex)
    except ValueError:
        return None
    
    if not script_bytes:
        return []
    
    if len(script_bytes) < 1:
        return []

    i = 0
    parsed_script = []
    while i < len(script_bytes):
        opcode = script_bytes[i]
        i += 1

        if 0x01 <= opcode <= 0x4B:
            data_len = opcode
            if i + data_len > len(script_bytes):
                return None
            data = script_bytes[i : i + data_len]
            parsed_script.append(data.hex())
            i += data_len
        elif opcode == 0x4C:
            if i + 1 > len(script_bytes): return None
            data_len = script_bytes[i]
            i += 1
            if i + data_len > len(script_bytes): return None
            data = script_bytes[i : i + data_len]
            parsed_script.append(data.hex())
            i += data_len
        elif opcode == 0x4D:
            if i + 2 > len(script_bytes): return None
            data_len = int.from_bytes(script_bytes[i : i + 2], 'little')
            i += 2
            if i + data_len > len(script_bytes): return None
            data = script_bytes[i : i + data_len]
            parsed_script.append(data.hex())
            i += data_len
        elif opcode == 0x4E:
            if i + 4 > len(script_bytes): return None
            data_len = int.from_bytes(script_bytes[i : i + 4], 'little')
            i += 4
            if i + data_len > len(script_bytes): return None
            data = script_bytes[i : i + data_len]
            parsed_script.append(data.hex())
            i += data_len
        else:
            parsed_script.append(opcode)
    return parsed_script

def extract_signatures(transactions_from_api_raw_details):
    signatures = []

    for txid, tx_data in transactions_from_api_raw_details.items():
        i = -1 
        try:
            raw_tx_hex = tx_data['raw_hex']
            
            if not isinstance(raw_tx_hex, str):
                print(f"{Colors.RED}ERROR: raw_tx_hex for {txid} is not a string (type: {type(raw_tx_hex)}). Skipping this transaction.{Colors.RESET}")
                continue

            parsed_tx_internal, is_segwit_actual = parse_raw_transaction_internal(raw_tx_hex)

            for i, input_data in enumerate(parsed_tx_internal['inputs']):
                script_sig_bytes = input_data['script_sig_bytes']
                script_sig_hex = binascii.hexlify(script_sig_bytes).decode()

                witness_data_bytes = []
                if is_segwit_actual and i < len(parsed_tx_internal.get('witnesses', [])):
                    witness_data_bytes = parsed_tx_internal['witnesses'][i]
                witness_data_hex = [binascii.hexlify(item).decode() for item in witness_data_bytes]

                spent_script_pubkey_bytes = None
                spent_utxo_value = None
                z_accuracy_status = "FALLBACK_TXID_HASH"
                calculated_z = int(sha256(bytes.fromhex(txid)).hexdigest(), 16)

                # --- SPECIAL HANDLING FOR COINBASE INPUTS ---
                if input_data['prev_tx_id_bytes'] == b'\x00' * 32 and input_data['output_idx'] == 0xFFFFFFFF:
                    z_accuracy_status = "COINBASE_INPUT_N/A_Z"
                    print(f"{Colors.YELLOW}  Info: Input {i} ({txid}) is a coinbase transaction. Standard Z calculation does not apply.{Colors.RESET}")
                else:
                    prev_tx_id_hex = binascii.hexlify(input_data['prev_tx_id_bytes']).decode()
                    output_idx = input_data['output_idx']
                    
                    spent_script_pubkey_bytes, spent_utxo_value = get_utxo_details_for_sighash(prev_tx_id_hex, output_idx)
                    
                    if spent_script_pubkey_bytes is not None and spent_utxo_value is not None:
                        try:
                            sighash_type_byte = 0x01
                            
                            if witness_data_hex and len(witness_data_hex[0]) >= 2:
                                try:
                                    potential_sighash_byte = int(witness_data_hex[0][-2:], 16)
                                    if 0 < potential_sighash_byte <= 0xff:
                                        sighash_type_byte = potential_sighash_byte
                                except ValueError:
                                    pass

                            elif script_sig_hex and len(script_sig_hex) >= 2:
                                try:
                                    parsed_script_sig = decode_script(script_sig_hex)
                                    if parsed_script_sig and isinstance(parsed_script_sig[0], str) and len(parsed_script_sig[0]) >= 2:
                                        potential_sighash_byte = int(parsed_script_sig[0][-2:], 16)
                                        if 0 < potential_sighash_byte <= 0xff:
                                            sighash_type_byte = potential_sighash_byte
                                except Exception:
                                    pass

                            calculated_z = get_sighash_z(
                                parsed_tx_internal, 
                                i, 
                                spent_script_pubkey_bytes, 
                                spent_utxo_value, 
                                sighash_type_byte, 
                                is_segwit_actual
                            )
                            z_accuracy_status = "ACCURATE"
                        except Exception as e:
                            print(f"{Colors.RED}  Error calculating accurate Z for input {i} ({txid}): {e}. Using fallback Z.{Colors.RESET}")
                            z_accuracy_status = "ERROR_Z_CALCULATION"
                    else:
                        print(f"{Colors.YELLOW}  Warning: Failed to get spent UTXO details for input {i} ({txid}). Using fallback Z.{Colors.RESET}")
                        z_accuracy_status = "FALLBACK_UTXO_FETCH_FAILED"


                signature_found = False
                current_public_key_hex = None
                current_all_public_keys_in_multisig = None
                current_type = 'Unknown'
                current_r = None
                current_s = None
                
                if witness_data_hex and len(witness_data_hex) >= 2:
                    witness_sig_hex_full = witness_data_hex[0]
                    
                    if len(witness_sig_hex_full) >= 2 and (witness_sig_hex_full.endswith('01') or witness_sig_hex_full.endswith('02') or witness_sig_hex_full.endswith('03') or witness_sig_hex_full.endswith('81') or witness_sig_hex_full.endswith('82') or witness_sig_hex_full.endswith('83')):
                        witness_sig_hex = witness_sig_hex_full[:-2] 
                    else:
                        witness_sig_hex = witness_sig_hex_full

                    witness_pubkey_hex = None
                    extracted_pubkeys_from_witness_script = []

                    if len(witness_data_hex) == 2 and ((len(witness_data_hex[1]) == 66 and witness_data_hex[1].startswith(('02', '03'))) or (len(witness_data_hex[1]) == 130 and witness_data_hex[1].startswith('04'))):
                        witness_pubkey_hex = witness_data_hex[1]
                        current_type = 'P2WPKH_ECDSA'
                    elif len(witness_data_hex) > 2 and isinstance(witness_data_hex[-1], str):
                        potential_witness_script_hex = witness_data_hex[-1]
                        decoded_witness_script = decode_script(potential_witness_script_hex)
                        if decoded_witness_script and \
                           decoded_witness_script and len(decoded_witness_script) >=2 and \
                           decoded_witness_script[0] in OP_N_MAPPING and \
                           decoded_witness_script[-1] == OP_CHECKMULTISIG:
                            m_val = OP_N_MAPPING.get(decoded_witness_script[0])
                            n_val = OP_N_MAPPING.get(decoded_witness_script[-2])
                            if m_val is not None and n_val is not None and m_val <= n_val:
                                current_type = f'P2WSH_Multisig_{m_val}_of_{n_val}_ECDSA'
                                for pk_candidate_idx in range(1, len(decoded_witness_script) - 2):
                                    pk_candidate = decoded_witness_script[pk_candidate_idx]
                                    if isinstance(pk_candidate, str) and ((len(pk_candidate) == 66 and pk_candidate.startswith(('02', '03'))) or (len(pk_candidate) == 130 and pk_candidate.startswith('04'))):
                                        extracted_pubkeys_from_witness_script.append(pk_candidate)
                                current_all_public_keys_in_multisig = extracted_pubkeys_from_witness_script
                                witness_pubkey_hex = extracted_pubkeys_from_witness_script[0] if extracted_pubkeys_from_witness_script else None
                        else:
                            current_type = 'P2WSH_ECDSA'
                    else:
                        current_type = 'SegWit_ECDSA'

                    current_r, current_s = parse_der_signature(witness_sig_hex)
                    current_public_key_hex = witness_pubkey_hex
                    signature_found = True

                elif script_sig_hex and not signature_found:
                    parsed_script = decode_script(script_sig_hex)
                    if parsed_script and len(parsed_script) > 1:
                        if isinstance(parsed_script[-1], str) and len(parsed_script[-1]) > 0: 
                            redeem_script_hex = parsed_script[-1]
                            decoded_redeem_script = decode_script(redeem_script_hex)
                            if decoded_redeem_script and len(decoded_redeem_script) >=2 and \
                               decoded_redeem_script[0] in OP_N_MAPPING and \
                               decoded_redeem_script[-1] == OP_CHECKMULTISIG:
                                m_val = OP_N_MAPPING.get(decoded_redeem_script[0])
                                n_val = OP_N_MAPPING.get(decoded_redeem_script[-2])
                                if m_val is not None and n_val is not None and m_val <= n_val:
                                    current_type = f'P2SH_Multisig_{m_val}_of_{n_val}_ECDSA'
                                    potential_sigs_data = parsed_script[1:-1]
                                    
                                    if potential_sigs_data and len(potential_sigs_data[0]) >= 2 and (potential_sigs_data[0].endswith('01') or potential_sigs_data[0].endswith('02') or potential_sigs_data[0].endswith('03') or potential_sigs_data[0].endswith('81') or potential_sigs_data[0].endswith('82') or potential_sigs_data[0].endswith('83')):
                                        sig_to_parse = potential_sigs_data[0][:-2] 
                                    else:
                                        sig_to_parse = potential_sigs_data[0]

                                    current_r, current_s = parse_der_signature(sig_to_parse)
                                    
                                    extracted_pubkeys = []
                                    for pk_candidate_idx in range(1, len(decoded_redeem_script) - 2):
                                        pk_candidate = decoded_redeem_script[pk_candidate_idx]
                                        if isinstance(pk_candidate, str) and ((len(pk_candidate) == 66 and pk_candidate.startswith(('02', '03'))) or (len(pk_candidate) == 130 and pk_candidate.startswith('04'))):
                                            extracted_pubkeys.append(pk_candidate)
                                    current_all_public_keys_in_multisig = extracted_pubkeys
                                    current_public_key_hex = extracted_pubkeys[0] if extracted_pubkeys else None
                                    signature_found = True
                                    
                        if not signature_found:
                            if len(parsed_script) == 2 and isinstance(parsed_script[0], str) and isinstance(parsed_script[1], str):
                                signature_hex_full = parsed_script[0]
                                if len(signature_hex_full) >= 2 and (signature_hex_full.endswith('01') or signature_hex_full.endswith('02') or signature_hex_full.endswith('03') or signature_hex_full.endswith('81') or signature_hex_full.endswith('82') or signature_hex_full.endswith('83')):
                                    sig_to_parse = signature_hex_full[:-2] 
                                else:
                                    sig_to_parse = signature_hex_full

                                current_r, current_s = parse_der_signature(sig_to_parse)
                                current_public_key_hex = parsed_script[1]
                                current_type = 'P2PKH_ECDSA'
                                signature_found = True

                if current_r is not None and current_s is not None and current_r != 0 and current_s != 0:
                    s_norm = current_s
                    if s_norm > N // 2:
                        s_norm = N - s_norm
                    
                    signatures.append({
                        'r': current_r, 
                        's': current_s,
                        's_norm': s_norm,
                        'z': calculated_z, 
                        'z_accuracy_status': z_accuracy_status,
                        'txid': txid,
                        'input_index': i,
                        'public_key': current_public_key_hex,
                        'all_public_keys_in_multisig': current_all_public_keys_in_multisig,
                        'type': current_type,
                        'script': script_sig_hex,
                        'witness': witness_data_hex 
                    })
                else:
                    print(f"{Colors.YELLOW}  Warning: Failed to parse signature or public key for input {i} ({txid}). Skipping.{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}Error processing transaction {txid} (input index: {i if i != -1 else 'N/A'}): {e}. Continuing.{Colors.RESET}")
            continue
    return signatures

def validate_private_key_and_address(private_key_int, target_address, relevant_public_keys_hex=None):
    if not (0 < private_key_int < N):
        return False, "Private key not within valid range (0 < d < N)"

    try:
        private_key_bytes = private_key_int.to_bytes(32, byteorder='big')
        
        signing_key = SigningKey.from_string(private_key_bytes, curve=SECP256k1)
        verifying_key = signing_key.get_verifying_key()
        
        derived_pubkey_compressed = point_to_pubkey_bytes(verifying_key.pubkey.point, compressed=True).hex()
        derived_pubkey_uncompressed = point_to_pubkey_bytes(verifying_key.pubkey.point, compressed=False).hex()

        # Check P2PKH addresses first
        derived_address_compressed = public_key_to_address(derived_pubkey_compressed, is_compressed=True, script_type='P2PKH')
        derived_address_uncompressed = public_key_to_address(derived_pubkey_uncompressed, is_compressed=False, script_type='P2PKH')
        
        # Check P2SH-P2WPKH (SegWit compatibility address)
        derived_p2sh_p2wpkh_address_compressed = public_key_to_address(derived_pubkey_compressed, is_compressed=True, script_type='P2SH-P2WPKH')
        
        if derived_address_compressed == target_address or derived_address_uncompressed == target_address or derived_p2sh_p2wpkh_address_compressed == target_address:
            return True, "MATCHES_TARGET_ADDRESS"

        if relevant_public_keys_hex:
            if not isinstance(relevant_public_keys_hex, list):
                relevant_public_keys_hex = [relevant_public_keys_hex]
            
            for pk_hex in relevant_public_keys_hex:
                if derived_pubkey_compressed == pk_hex or derived_pubkey_uncompressed == pk_hex:
                    return True, "MATCHES_RELEVANT_PUBLIC_KEY"

        return False, f"Derived addresses ({derived_address_compressed}/{derived_address_uncompressed}) and public key ({derived_pubkey_compressed}) do not match target or relevant public keys."
            
    except Exception as e:
        return False, f"Error during private key/address validation: {e}"

def private_key_to_wif(private_key_int):
    private_key_bytes = private_key_int.to_bytes(32, byteorder='big')
    data = b'\x80' + private_key_bytes + b'\x01'
    checksum = sha256(sha256(data).digest()).digest()[:4]
    wif = encode_base58(data + checksum)
    return wif

def count_leading_zeros(n, bit_length=256):
    if n == 0:
        return bit_length
    return bit_length - n.bit_length()

def is_low_order(r, s):
    if r == 0 or s == 0:
        return True
    return False

def check_nonce_bias_heuristics(signatures):
    vulnerabilities = []
    
    for sig in signatures:
        r = sig['r']
        s = sig['s']

        if r < 1000:  
            vulnerabilities.append({
                'type': 'Nonce Bias (Small R)',
                'txid': sig['txid'],
                'r': r,
                's': s,
                'z': sig['z'],
                'input_index': sig['input_index'],
                'public_key': sig['public_key'],
                'script': sig['script'],
                'issue': f'The "r" value is unusually small ({r}). This may indicate a biased nonce generation.',
                'method': 'Statistical analysis of "r" value distribution.',
                'confidence': 'Low',
                'signature_type': sig.get('type', 'Unknown'),
                'z_accuracy_status': sig.get('z_accuracy_status', 'UNKNOWN')
            })
            VULN_COUNTS['Nonce Bias (Small R)'] += 1
            VULN_COUNTS['Weak RNG (Statistical)'] += 1

        if count_leading_zeros(r) > 10:  
            vulnerabilities.append({
                'type': 'Nonce Bias (Leading Zeros in R)',
                'txid': sig['txid'],
                'r': r,
                's': s,
                'z': sig['z'],
                'input_index': sig['input_index'],
                'public_key': sig['public_key'],
                'script': sig['script'],
                'issue': f'The "r" value has an unusually high number of leading zeros ({count_leading_zeros(r)}).',
                'method': 'Statistical analysis of bit patterns of "r" value.',
                'confidence': 'Low',
                'signature_type': sig.get('type', 'Unknown'),
                'z_accuracy_status': sig.get('z_accuracy_status', 'UNKNOWN')
            })
            VULN_COUNTS['Nonce Bias (Leading Zeros in R)'] += 1
            VULN_COUNTS['Weak RNG (Statistical)'] += 1
        
        if count_leading_zeros(s) > 10:
            vulnerabilities.append({
                'type': 'Nonce Bias (Leading Zeros in S)',
                'txid': sig['txid'],
                'r': r,
                's': s,
                'z': sig['z'],
                'input_index': sig['input_index'],
                'public_key': sig['public_key'],
                'script': sig['script'],
                'issue': f'The "s" value has an unusually high number of leading zeros ({count_leading_zeros(s)}).',
                'method': 'Statistical analysis of bit patterns of "s" value.',
                'confidence': 'Low',
                'signature_type': sig.get('type', 'Unknown'),
                'z_accuracy_status': sig.get('z_accuracy_status', 'UNKNOWN')
            })
            VULN_COUNTS['Nonce Bias (Leading Zeros in S)'] += 1
            VULN_COUNTS['Weak RNG (Statistical)'] += 1
            
    return vulnerabilities

def check_lll_attack_nonce_bias(signatures_by_pubkey):
    lll_vulnerabilities = []

    for pubkey_group_key, sig_list in signatures_by_pubkey.items():
        if len(sig_list) < 2:
            continue

        sorted_sig_list = sorted(sig_list, key=lambda x: (x['r'], x['s']))

        for i in range(len(sorted_sig_list)):
            for j in range(i + 1, len(sorted_sig_list)):
                sig1 = sorted_sig_list[i]
                sig2 = sorted_sig_list[j]

                if pubkey_group_key != sig1.get('public_key') and \
                   pubkey_group_key != tuple(sorted(sig1.get('all_public_keys_in_multisig', []))) and \
                   pubkey_group_key != tuple(sorted(sig2.get('all_public_keys_in_multisig', []))):
                   continue

                leading_zeros_s1 = count_leading_zeros(sig1['s'])
                leading_zeros_s2 = count_leading_zeros(sig2['s'])
                
                leading_zeros_r1 = count_leading_zeros(sig1['r'])
                leading_zeros_r2 = count_leading_zeros(sig2['r'])

                ZERO_BIAS_THRESHOLD = 10 

                is_vulnerable = False
                issue_description = []

                if leading_zeros_s1 >= ZERO_BIAS_THRESHOLD and leading_zeros_s2 >= ZERO_BIAS_THRESHOLD:
                    issue_description.append(f"Both 's' values have an unusually high number of leading zeros (Sig1: {leading_zeros_s1}, Sig2: {leading_zeros_s2}) with the same {2 if isinstance(pubkey_group_key, str) else len(pubkey_group_key)} public key(s).")
                    is_vulnerable = True
                elif leading_zeros_r1 >= ZERO_BIAS_THRESHOLD and leading_zeros_r2 >= ZERO_BIAS_THRESHOLD:
                    issue_description.append(f"Both 'r' values have an unusually high number of leading zeros (Sig1: {leading_zeros_r1}, Sig2: {leading_zeros_r2}) with the same {2 if isinstance(pubkey_group_key, str) else len(pubkey_group_key)} public key(s).")
                    is_vulnerable = True
                
                if is_vulnerable:
                    lll_vulnerabilities.append({
                        'type': 'LLL Attack (Bias S/R)',
                        'txid': sig1['txid'],
                        'txid2': sig2['txid'],
                        'input_index': sig1['input_index'],
                        'input_index2': sig2['input_index'],
                        'r1': sig1['r'], 
                        's1': sig1['s'], 
                        'z1': sig1['z'], 
                        'r2': sig2['r'],
                        's2': sig2['s'],
                        'z2': sig2['z'],
                        'public_key': sig1['public_key'] if sig1['public_key'] else pubkey_group_key,
                        'issue': " ".join(issue_description),
                        'method': 'Statistical analysis of "s" or "r" value bit patterns with same public keys.',
                        'confidence': 'Medium',
                        'signature_type': sig1.get('type', 'Unknown'),
                        'z_accuracy_status': sig1.get('z_accuracy_status', 'UNKNOWN')
                    })
                    VULN_COUNTS['LLL Attack (Bias S/R)'] += 1
                    VULN_COUNTS['Weak RNG'] += 1
    return lll_vulnerabilities

def check_for_non_canonical_signatures(signatures):
    vulnerabilities = []
    for sig in signatures:
        s = sig['s']
        if "ECDSA" in sig.get('type', ''): 
            if s > S_MAX_HALF:
                vulnerabilities.append({
                    'type': 'Non-Canonical Signature',
                    'txid': sig['txid'],
                    'r': sig['r'],
                    's': s, 
                    'z': sig['z'],
                    'input_index': sig['input_index'],
                    'public_key': sig['public_key'],
                    'script': sig['script'],
                    'issue': f"The signature's 's' value ({hex(s)}) is non-canonical (greater than N/2).",
                    'method': 'Direct comparison with N/2.',
                    'confidence': 'Informative',
                    'validation_status': 'Valid (but non-standard)',
                    'signature_type': sig.get('type', 'Unknown'),
                    'z_accuracy_status': sig.get('z_accuracy_status', 'UNKNOWN')
                })
                VULN_COUNTS['Non-Canonical Signature'] += 1
    return vulnerabilities

def check_for_guessable_small_k(signatures, target_address, max_k_attempt_limit):
    vulnerabilities = []

    if max_k_attempt_limit <= 0:
        return vulnerabilities

    heuristic_k_candidates = set()
    for i in range(1, min(max_k_attempt_limit + 1, 1000)):
        heuristic_k_candidates.add(i)
    
    for i in range(1, 257):
        val = 2**i
        if val <= max_k_attempt_limit:
            heuristic_k_candidates.add(val)
        else:
            break
            
    for length in range(1, 33):
        val = (1 << length) - 1
        if val <= max_k_attempt_limit:
            heuristic_k_candidates.add(val)
        else:
            break
            
    sorted_k_candidates = sorted(list(heuristic_k_candidates))

    if max_k_attempt_limit > 1000:
        for i in range(1001, max_k_attempt_limit + 1):
            sorted_k_candidates.append(i)


    for sig_idx, sig in enumerate(signatures): 
        r = sig['r']
        s = sig['s']
        z = sig['z']
        txid = sig['txid']
        sig_type = sig.get('type', 'Unknown')
        input_index = sig['input_index']
        public_key_hex = sig['public_key']
        script_hex = sig['script']

        if sig['z_accuracy_status'] != "ACCURATE":
            continue

        if r == 0: 
            continue

        try:
            inv_r = inverse_mod(r, N)
        except ZeroDivisionError: 
            continue

        for k_candidate in sorted_k_candidates:
            if k_candidate >= N: 
                break

            private_key_candidate = (s * k_candidate - z) * inv_r % N
            
            if 0 < private_key_candidate < N: 
                relevant_pks = [public_key_hex] if public_key_hex else []
                if sig.get('all_public_keys_in_multisig'):
                    relevant_pks.extend(sig['all_public_keys_in_multisig'])
                relevant_pks = list(set(relevant_pks))

                is_valid, validation_msg = validate_private_key_and_address(private_key_candidate, target_address, relevant_pks)
                if is_valid:
                    vulnerabilities.append({
                        'type': 'Guessable Small K-Value',
                        'private_key': private_key_candidate,
                        'private_key_hex': hex(private_key_candidate),
                        'private_key_wif': private_key_to_wif(private_key_candidate),
                        'transactions': [txid],
                        'r': r,
                        's': s,
                        'z': z,
                        'k_value_recovered': k_candidate,
                        'input_index': input_index,
                        'public_key': public_key_hex,
                        'script': script_hex,
                        'issue': f'Private key recovered due to a guessable small nonce (k={k_candidate}).',
                        'method': f'Brute-force small k values up to {max_k_attempt_limit} using heuristic patterns and linear search.',
                        'confidence': '100%',
                        'validation_status': validation_msg,
                        'signature_type': sig_type,
                        'z_accuracy_status': sig.get('z_accuracy_status', 'UNKNOWN')
                    })
                    VULN_COUNTS['Guessable Small K-Value'] += 1
                    VULN_COUNTS['Weak RNG'] += 1 
                    return vulnerabilities 
    return vulnerabilities

def check_for_multi_nonce_delta(signatures, target_address):
    vulnerabilities = []
    signatures_by_pubkey = defaultdict(list)
    for sig in signatures:
        if sig.get('all_public_keys_in_multisig'):
            pubkey_group_key = tuple(sorted(sig['all_public_keys_in_multisig']))
            signatures_by_pubkey[pubkey_group_key].append(sig)
        elif sig.get('public_key'):
            signatures_by_pubkey[sig['public_key']].append(sig)

    for pub_key_or_group, sig_list in signatures_by_pubkey.items():
        if len(sig_list) < 2:
            continue

        for i in range(len(sig_list)):
            for j in range(i + 1, len(sig_list)):
                sig1 = sig_list[i]
                sig2 = sig_list[j]

                r1, s1, z1 = sig1['r'], sig1['s'], sig1['z']
                r2, s2, z2 = sig2['r'], sig2['s'], sig2['z']

                if r1 == r2:
                    continue

                R_CLOSE_THRESHOLD = 1000 
                if abs(r1 - r2) < R_CLOSE_THRESHOLD:
                    vulnerabilities.append({
                        'type': 'Multi-Nonce Delta',
                        'txid': sig1['txid'],
                        'txid2': sig2['txid'], 
                        'r1': r1, 's1': s1, 'z1': z1,
                        'r2': r2, 's2': s2, 'z2': z2,
                        'input_index1': sig1['input_index'],
                        'input_index2': sig2['input_index'],
                        'public_key': pub_key_or_group if isinstance(pub_key_or_group, str) else list(pub_key_or_group)[0],
                        'issue': f'Two signatures from the same public key have very close R values (delta: {abs(r1-r2)}). This might indicate a flawed nonce generator producing related nonces.',
                        'method': f'Comparison of R values (R1={r1}, R2={r2}).',
                        'confidence': 'Medium',
                        'validation_status': 'Requires further analysis',
                        'signature_type': sig1.get('type', 'Unknown'),
                        'z_accuracy_status': sig1.get('z_accuracy_status', 'UNKNOWN')
                    })
                    VULN_COUNTS['Multi-Nonce Delta'] += 1
                    VULN_COUNTS['Weak RNG'] += 1 

    return vulnerabilities


def check_for_vulnerabilities(signatures, target_address):
    vulnerabilities = defaultdict(list)
    
    nonce_reuse_candidates_map = defaultdict(list)
    for sig in signatures:
        nonce_reuse_candidates_map[(sig['r'], sig['s_norm'])].append(sig)


    print(f"\n{Colors.BLUE}Searching for Reused Nonce...{Colors.RESET}")
    for (r_val, s_norm_val), sig_list in nonce_reuse_candidates_map.items():
        if len(sig_list) > NONCE_BIAS_THRESHOLD:
            accurate_sig_list = [s for s in sig_list if s['z_accuracy_status'] == "ACCURATE"]
            
            if len(accurate_sig_list) < 2:
                continue

            sig1_for_calc = None
            sig2_for_calc = None
            for i in range(len(accurate_sig_list)):
                for j in range(i + 1, len(accurate_sig_list)):
                    if accurate_sig_list[i]['z'] != accurate_sig_list[j]['z']:
                        sig1_for_calc = accurate_sig_list[i]
                        sig2_for_calc = accurate_sig_list[j]
                        break
                if sig1_for_calc and sig2_for_calc: break

            if sig1_for_calc and sig2_for_calc:
                print(f"{Colors.BRIGHT_YELLOW}Detection: Potential Reused Nonce detected with accurate Z! r={hex(r_val)[:10]}..., s_norm={hex(s_norm_val)[:10]}... ({len(accurate_sig_list)} occurrences with accurate Z){Colors.RESET}")
                try:
                    s_diff = (sig1_for_calc['s_norm'] - sig2_for_calc['s_norm']) % N
                    if s_diff == 0:
                        print(f"{Colors.YELLOW}  Warning: (s1_norm - s2_norm) = 0. Cannot compute k from this pair.{Colors.RESET}")
                        continue

                    s_diff_inv = inverse_mod(s_diff, N)
                    k_val = ((sig1_for_calc['z'] - sig2_for_calc['z']) * s_diff_inv) % N
                    
                    private_key_recovered = (sig1_for_calc['s_norm'] * k_val - sig1_for_calc['z']) * inverse_mod(sig1_for_calc['r'], N) % N
                    
                    relevant_pks = set()
                    for s_data in accurate_sig_list:
                        if s_data.get('public_key'):
                            relevant_pks.add(s_data['public_key'])
                        if s_data.get('all_public_keys_in_multisig'):
                            for pk in s_data['all_public_keys_in_multisig']:
                                relevant_pks.add(pk)
                    relevant_pks = list(relevant_pks)
                    
                    is_valid, validation_msg = validate_private_key_and_address(private_key_recovered, target_address, relevant_pks)

                    if private_key_recovered > 0 and private_key_recovered < N and is_valid:
                        print(f"{Colors.BRIGHT_GREEN}  Private Key found via Reused Nonce: {hex(private_key_recovered)}{Colors.RESET}")
                        vulnerabilities['Reused Nonce'].append({
                            'type': 'Reused Nonce',
                            'private_key': private_key_recovered,
                            'private_key_hex': hex(private_key_recovered),
                            'private_key_wif': private_key_to_wif(private_key_recovered),
                            'transactions': sorted(list(set([s['txid'] for s in sig_list]))),
                            'r': r_val, 
                            's_values': [sig['s'] for sig in sig_list],
                            'z_values': [sig['z'] for sig in sig_list],
                            'k_value': k_val,
                            'input_index': sig1_for_calc['input_index'], 
                            'public_key': sig1_for_calc.get('public_key') or (list(sig1_for_calc['all_public_keys_in_multisig'])[0] if sig1_for_calc.get('all_public_keys_in_multisig') else None),
                            'issue': 'Private key recovered due to nonce reuse (same r, different s, different message) with accurate Z.',
                            'method': 'd = (s*k - z) * inv(r) mod N (where k derived from k = (z1-z2)*(s1-s2)^-1)',
                            'confidence': '100%',
                            'validation_status': validation_msg,
                            'signature_type': sig1_for_calc.get('type', 'Unknown'),
                            'z_accuracy_status': "ACCURATE"
                        })
                        VULN_COUNTS['Reused Nonce'] += 1
                        VULN_COUNTS['K-Value Issues'] += 1
                    else:
                        vulnerabilities['K-Value Issues'].append({
                            'type': 'K-Value Issues (Reused Nonce Derivation Failed Validation)',
                            'r': r_val, 
                            'k_candidate': k_val,
                            'transactions': sorted(list(set([s['txid'] for s in sig_list]))),
                            's_values': [sig['s'] for sig in sig_list],
                            'z_values': [sig['z'] for sig in sig_list],
                            'input_index': sig1_for_calc['input_index'], 
                            'public_key': sig1_for_calc.get('public_key') or (list(sig1_for_calc['all_public_keys_in_multisig'])[0] if sig1_for_calc.get('all_public_keys_in_multisig') else None),
                            'script': sig1_for_calc['script'], 
                            'issue': f'Potential K-value issue: k derived from a reused nonce, but private key validation failed (Z accurate: {sig1_for_calc["z_accuracy_status"]}). This could indicate a false positive or a more complex scenario.',
                            'method': 'd = (s*k - z) * inv(r) mod N (where k derived from k = (z1-z2)*(s1-s2)^-1)',
                            'confidence': 'Low (validation failed)',
                            'validation_status': validation_msg,
                            'signature_type': sig1_for_calc.get('type', 'Unknown'),
                            'z_accuracy_status': sig1_for_calc.get('z_accuracy_status', 'UNKNOWN')
                        })
                        VULN_COUNTS['K-Value Issues'] += 1 

                except ZeroDivisionError:
                    print(f"{Colors.YELLOW}  Warning: Division by zero when calculating k from nonce reuse.{Colors.RESET}")
                except Exception as e:
                    print(f"{Colors.RED}  Error in Reused Nonce calculation: {e}. Continuing.{Colors.RESET}")

    signatures_by_pubkey = defaultdict(list)
    for sig in signatures:
        if sig.get('all_public_keys_in_multisig'):
            pubkey_group_key = tuple(sorted(sig['all_public_keys_in_multisig']))
            signatures_by_pubkey[pubkey_group_key].append(sig)
        elif sig.get('public_key'):
            signatures_by_pubkey[sig['public_key']].append(sig)

    print(f"\n{Colors.BLUE}Searching for LLL Attack (S/R Bias)...{Colors.RESET}")
    lll_attack_findings = check_lll_attack_nonce_bias(signatures_by_pubkey)
    for vuln in lll_attack_findings:
        vulnerabilities[vuln['type']].append(vuln)

    multi_nonce_delta_findings = check_for_multi_nonce_delta(signatures, target_address)
    for vuln in multi_nonce_delta_findings:
        vulnerabilities[vuln['type']].append(vuln)

    for sig in signatures:
        if is_low_order(sig['r'], sig['s']):
            vulnerabilities['Low Order Points'].append({
                'txid': sig['txid'],
                'r': sig['r'],
                's': sig['s'],
                'z': sig['z'],
                'input_index': sig['input_index'],
                'public_key': sig['public_key'],
                'script': sig['script'],
                'issue': 'Signature uses an r or s value indicating a low-order k (r=0 or s=0).',
                'method': 'Heuristic check on r and s values',
                'confidence': 'Medium',
                'signature_type': sig.get('type', 'Unknown'),
                'z_accuracy_status': sig.get('z_accuracy_status', 'UNKNOWN')
            })
            VULN_COUNTS['Low Order Points'] += 1
            VULN_COUNTS['K-Value Issues'] += 1

    nonce_bias_findings = check_nonce_bias_heuristics(signatures)
    for vuln in nonce_bias_findings:
        vulnerabilities[vuln['type']].append(vuln)

    non_canonical_findings = check_for_non_canonical_signatures(signatures)
    for vuln in non_canonical_findings:
        vulnerabilities[vuln['type']].append(vuln)

    small_k_findings = check_for_guessable_small_k(signatures, target_address, GLOBAL_MAX_SMALL_K_ATTEMPT)
    for vuln in small_k_findings:
        vulnerabilities[vuln['type']].append(vuln)

    print(f"\n{Colors.BLUE}Searching for Fault Attacks (inconsistent s)...{Colors.RESET}")
    fault_candidates_map = defaultdict(list)
    for sig_data in signatures:
        fault_candidates_map[(sig_data['r'], sig_data['z'])].append(sig_data['s'])

    for (r_val, z_val), s_values in fault_candidates_map.items():
        if len(s_values) >= 2:
            unique_s_values = list(set(s_values))
            if len(unique_s_values) >= 2:
                for i in range(len(unique_s_values)):
                    for j in range(i + 1, len(unique_s_values)):
                        s1 = unique_s_values[i]
                        s2 = unique_s_values[j]
                        if s1 != s2 and s1 != (N - s2) % N:
                            print(f"{Colors.BRIGHT_RED}  Detection: Potential Fault Attack detected! (r={hex(r_val)[:10]}..., z={hex(z_val)[:10]}...). s1={hex(s1)[:10]}..., s2={hex(s2)[:10]}...{Colors.RESET}")
                            vulnerabilities['Fault Attack'].append({
                                'type': 'Fault Attack',
                                'r': hex(r_val),
                                'z': hex(z_val),
                                's_values': [hex(s) for s in unique_s_values],
                                'transactions': sorted(list(set([s['txid'] for s in signatures if s['r'] == r_val and s['z'] == z_val]))),
                                'issue': 'Two signatures have inconsistent "s" values for the same "r" and "z". This indicates a potential fault injection.',
                                'method': 'Comparison of "s" values for identical (r,z) pairs.',
                                'confidence': 'High',
                                'validation_status': 'Cryptographic Anomaly',
                                'signature_type': signatures[0].get('type', 'Unknown') if signatures else 'Unknown',
                                'z_accuracy_status': signatures[0].get('z_accuracy_status', 'UNKNOWN') if signatures else 'UNKNOWN'
                            })
                            VULN_COUNTS['Fault Attack'] += 1
                            VULN_COUNTS['Weak RNG'] += 1

    print(f"\n{Colors.BLUE}Lattice attack detection is not implemented in this version (highly complex, requires external libraries).{Colors.RESET}")

    return vulnerabilities

def analyze_address(address):
    global SCANNED_ADDRESSES, VULNERABLE_ADDRESSES, CURRENT_ADDRESS, SCANNED_ADDRESS_LIST, REPORTS
    
    CURRENT_ADDRESS = address
    display_stats()

    report = {
        'address': address,
        'vulnerabilities': [],
        'scan_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'transaction_count': 0,
        'signature_count': 0
    }
    
    total_txs, used_api_conf = get_total_transactions(address)

    tx_hashes_from_address = []
    if total_txs > 0 and used_api_conf:
        offset = 0
        current_before_txid = None 
        
        endpoint_str = used_api_conf['tx_list_endpoint']
        has_offset_param = '{offset}' in endpoint_str
        has_limit_param = '{limit}' in endpoint_str
        has_before_txid_param = '{before_txid}' in endpoint_str

        while True:
            format_params = {'address': address}
            
            if has_offset_param:
                format_params['offset'] = offset
            if has_limit_param:
                format_params['limit'] = 100
            if has_before_txid_param:
                if current_before_txid:
                    format_params['before_txid'] = current_before_txid
                elif offset > 0:
                    print(f"{Colors.YELLOW}Warning: No 'before_txid' for pagination after initial batch. Stopping pagination for {used_api_conf['base_url']}.{Colors.RESET}")
                    break

            try:
                api_name_for_retries = next(k for k,v in API_CONFIGS.items() if v == used_api_conf)
                paginated_url = used_api_conf['base_url'] + endpoint_str.format(**format_params)
            except KeyError as e:
                print(f"{Colors.RED}ERROR: Tx list endpoint '{endpoint_str}' for {api_name_for_retries} expects parameter '{e}' but none provided (dynamic formatting failed). Skipping this API for tx list.{Colors.RESET}")
                break
            except StopIteration:
                print(f"{Colors.RED}ERROR: API config not found for the used endpoint. Skipping.{Colors.RESET}")
                break

            list_data = _make_api_request_with_retries(paginated_url, api_name=api_name_for_retries)
            if list_data:
                current_batch_txids = used_api_conf['parser']['transactions_from_list'](list_data)
                if not current_batch_txids:
                    break

                tx_hashes_from_address.extend(current_batch_txids)
                if MAX_TRANSACTIONS > 0 and len(tx_hashes_from_address) >= MAX_TRANSACTIONS:
                    tx_hashes_from_address = tx_hashes_from_address[:MAX_TRANSACTIONS]
                    break

                if has_offset_param:
                    offset += len(current_batch_txids)
                elif has_before_txid_param: 
                    current_before_txid = current_batch_txids[-1] 
                    if not current_batch_txids or current_before_txid == tx_hashes_from_address[0]:
                        break
                if not has_offset_param and not has_limit_param and not has_before_txid_param:
                    break
            else:
                print(f"{Colors.YELLOW}Warning: Failed to get TXID list from {api_name_for_retries}. Stopping pagination for this API.{Colors.RESET}")
                break
            time.sleep(SCAN_DELAY_SECONDS) # Add configurable delay
    else:
        print(f"{Colors.YELLOW}Warning: The API '{next(k for k,v in API_CONFIGS.items() if v == used_api_conf)}' does not have a transaction list endpoint. Cannot fetch TXIDs.{Colors.RESET}")


    if not tx_hashes_from_address:
        print(f"{Colors.YELLOW}No TXIDs found for address {address}. Skipping signature analysis.{Colors.RESET}")
        report['transaction_count'] = 0
        REPORTS.append(report)
        SCANNED_ADDRESSES += 1
        return None

    transactions_with_raw_details = {}
    for txid in tx_hashes_from_address:
        if EXIT_FLAG: break
        raw_hex = get_raw_hex_for_txid(txid) 
        if raw_hex:
            transactions_with_raw_details[txid] = {
                'raw_hex': raw_hex,
                'tx_details_mock': None
            }
        else:
            print(f"{Colors.YELLOW}Warning: Failed to get raw hex for TXID {txid}. Cannot analyze this signature.{Colors.RESET}")
        time.sleep(SCAN_DELAY_SECONDS) # Add configurable delay

    report['transaction_count'] = len(transactions_with_raw_details)
    
    signatures = extract_signatures(transactions_with_raw_details)

    if not signatures:
        report['signature_count'] = 0
        REPORTS.append(report)
        SCANNED_ADDRESSES += 1
        return None
    
    report['signature_count'] = len(signatures)
    
    found_vulnerabilities = check_for_vulnerabilities(signatures, address)
    
    if found_vulnerabilities:
        unique_vuln_types = set()
        for vuln_type, vulns_list in found_vulnerabilities.items():
            report['vulnerabilities'].extend(vulns_list)
            for vuln_detail in vulns_list:
                unique_vuln_types.add(vuln_detail['type'])
        
        if report['vulnerabilities']: 
            VULNERABLE_ADDRESSES += 1
            for vuln_type_name in unique_vuln_types:
                # Pass transactions_with_raw_details to save_report
                save_report(address, report, vuln_type_name, transactions_with_raw_details) 
        REPORTS.append(report) 
    else:
        # Pass transactions_with_raw_details to save_report even if no vulnerabilities
        save_report(address, report, "No Vulnerability", transactions_with_raw_details) 
        REPORTS.append(report)

    SCANNED_ADDRESSES += 1
    SCANNED_ADDRESS_LIST.append(address)
    display_stats()
    return report

def get_binary_representation(n, bit_length=256):
    if n is None:
        return "N/A"
    return bin(n)[2:].zfill(bit_length)

def save_report(address, report_data, vuln_subfolder=None, transactions_raw_data=None):
    base_report_dir = "reports"
    
    # Base directory for this specific vulnerability type
    if vuln_subfolder:
        safe_vuln_subfolder = "".join(c for c in vuln_subfolder if c.isalnum() or c in [' ', '_', '-']).replace(" ", "_")
        # Now, append the address to the report_dir
        report_dir = os.path.join(base_report_dir, safe_vuln_subfolder, address) 
    else:
        report_dir = os.path.join(base_report_dir, "General_Reports", address) # For no specific vuln type

    os.makedirs(report_dir, exist_ok=True) 

    filename = os.path.join(report_dir, f"{address}_report.txt")
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("="*80 + "\n")
        f.write(f"Signature Scanner for Bitcoin Vulnerability Report\n")
        f.write("="*80 + "\n")
        f.write(f"Scan Time: {report_data['scan_time']}\n")
        f.write(f"Address: {address}\n")
        f.write(f"Total Transactions: {report_data['transaction_count']}\n")
        f.write(f"Signatures Analyzed: {report_data['signature_count']}\n")
        f.write("="*80 + "\n\n")
        
        if not report_data['vulnerabilities']:
            f.write("✅ No vulnerabilities detected\n")
        else:
            filtered_vulns = []
            if vuln_subfolder and vuln_subfolder != "No Vulnerability": 
                filtered_vulns = [v for v in report_data['vulnerabilities'] if v['type'] == vuln_subfolder]
            else: 
                filtered_vulns = report_data['vulnerabilities']

            if not filtered_vulns: 
                f.write("No specific vulnerabilities of this type found in the context of this report.\n")
            else:
                for i, vuln in enumerate(filtered_vulns, 1):
                    status_emoji = "🔴"
                    if vuln['type'] == "Non-Canonical Signature":
                        status_emoji = "🟢"
                    elif "Nonce Bias" in vuln['type'] or "Weak RNG (Statistical)" == vuln['type'] or "K-Value Issues (Reused Nonce Derivation Failed Validation)" == vuln['type']:
                        status_emoji = "🟡"
                    elif vuln['type'] == "LLL Attack (Bias S/R)":
                        status_emoji = "🟠"

                    f.write(f"{status_emoji} VULNERABILITY #{i}: {vuln['type']}\n")
                    f.write("-"*80 + "\n")
                    
                    f.write(f"TXID: {vuln.get('txid', 'N/A')}\n")
                    if vuln['type'] == 'Multi-Nonce Delta' or vuln['type'] == 'LLL Attack (Bias S/R)': 
                        f.write(f"TXID 1: {vuln.get('txid', 'N/A')}\n")
                        f.write(f"TXID 2: {vuln.get('txid2', 'N/A')}\n")

                    f.write(f"Input Index: {vuln.get('input_index', 'N/A')}\n")
                    if vuln['type'] == 'Multi-Nonce Delta' or vuln['type'] == 'LLL Attack (Bias S/R)': 
                        f.write(f"Input Index 1: {vuln.get('input_index1', 'N/A')}\n")
                        f.write(f"Input Index 2: {vuln.get('input_index2', 'N/A')}\n")

                    k_value_to_display = None
                    if 'k_value' in vuln:
                        k_value_to_display = vuln['k_value']
                    elif 'k_value_recovered' in vuln:
                        k_value_to_display = vuln['k_value_recovered']
                    elif 'k_candidate' in vuln:
                        k_value_to_display = vuln['k_candidate']
                    
                    if k_value_to_display is not None:
                        f.write(f"K-value: {k_value_to_display}\n")
                        f.write(f"K-value (hex): {hex(k_value_to_display)}\n")
                        k_bin = get_binary_representation(k_value_to_display)
                        f.write(f"K-value MSB: {k_bin[:32]}\n")
                        f.write(f"K-value LSB: {k_bin[-32:]}\n")
                    else:
                        f.write("K-value: N/A (Not directly derived for this vulnerability type)\n")
                        f.write("K-value (hex): N/A\n")
                        f.write("K-value MSB: N/A\n")
                        f.write("K-value LSB: N/A\n")
                        
                    if vuln['type'] == 'Multi-Nonce Delta' or vuln['type'] == 'LLL Attack (Bias S/R)': 
                        f.write(f"r1: {hex(vuln.get('r1', 0))}\n")
                        f.write(f"r2: {hex(vuln.get('r2', 0))}\n")
                        f.write(f"s1: {hex(vuln.get('s1', 0))}\n")
                        f.write(f"s2: {hex(vuln.get('s2', 0))}\n")
                    else:
                        f.write(f"r: {hex(vuln.get('r_value') or vuln.get('r', 0))}\n") 
                        f.write(f"s: {hex(vuln['s'])}\n")
                    
                    if 'z_values' in vuln and len(vuln['z_values']) > 0:
                        for j, z_val in enumerate(vuln['z_values']):
                            f.write(f"z (Sig {j+1}): {hex(z_val)}\n")
                    elif vuln['type'] == 'Multi-Nonce Delta' or vuln['type'] == 'LLL Attack (Bias S/R)': 
                        f.write(f"z1: {hex(vuln.get('z1', 0))}\n")
                        f.write(f"z2: {hex(vuln.get('z2', 0))}\n")
                    else:
                        f.write(f"z: {hex(vuln['z'])}\n")
                    
                    f.write(f"Z Accuracy Status: {vuln.get('z_accuracy_status', 'UNKNOWN')}\n")

                    f.write(f"Script: {vuln.get('script', 'N/A')}\n")
                    if vuln.get('all_public_keys_in_multisig'):
                        f.write("Public Key (Multisig):\n")
                        for pk_hex in vuln['all_public_keys_in_multisig']:
                            f.write(f"  - {pk_hex}\n")
                    else:
                        f.write(f"Public Key: {vuln.get('public_key', 'N/A')}\n")

                    if 'private_key' in vuln:
                        f.write(f"PRIVATE KEY: {vuln['private_key']}\n")
                        f.write(f"PRIVATE KEY (hex): {vuln['private_key_hex']}\n")
                        if 'private_key_wif' in vuln:
                            f.write(f"PRIVATE KEY (WIF): {vuln['private_key_wif']}\n")
                    
                    if 'issue' in vuln:
                        f.write(f"Issue: {vuln['issue']}\n")
                    if 'method' in vuln:
                        f.write(f"Method: {vuln['method']}\n")
                    if 'confidence' in vuln:
                        f.write(f"Confidence: {vuln['confidence']}\n")
                    if 'validation_status' in vuln:
                        f.write(f"Validation Status: {vuln['validation_status']}\n")
                    if 'signature_type' in vuln:
                        f.write(f"Signature Type: {vuln['signature_type']}\n")
                    
                    if 'transactions' in vuln and len(vuln['transactions']) > 1:
                        f.write("\nAffected Transactions (multiple):\n")
                        for j, txid_affected in enumerate(vuln['transactions'], 1):
                            f.write(f"{j}. TXID: {txid_affected}\n")
                    
                    f.write("\n" + "="*80 + "\n\n")

                    # --- Save TXID JSON details ---
                    if vuln.get('txid') and transactions_raw_data and vuln['txid'] in transactions_raw_data:
                        tx_id_to_save = vuln['txid']
                        tx_data_for_json = transactions_raw_data[tx_id_to_save]
                        
                        # Create the nested txid_details folder
                        txid_details_folder = os.path.join(report_dir, "txid_details")
                        os.makedirs(txid_details_folder, exist_ok=True)

                        json_filename = os.path.join(txid_details_folder, f"{tx_id_to_save}_details.json")
                        
                        try:
                            with open(json_filename, 'w', encoding='utf-8') as json_f:
                                json.dump(tx_data_for_json, json_f, indent=4)
                            f.write(f"Raw transaction details saved to: {json_filename}\n")
                            print(f"{Colors.GREEN}Raw transaction details for {tx_id_to_save} saved to: {json_filename}{Colors.RESET}")
                        except Exception as json_e:
                            f.write(f"Warning: Failed to save JSON for TXID {tx_id_to_save}: {json_e}\n")
                            print(f"{Colors.YELLOW}Warning: Failed to save JSON for TXID {tx_id_to_save}: {json_e}{Colors.RESET}")


        f.write("\nSignature Scanner for Bitcoin Vulnerability\n")
        f.write("="*80 + "\n")

    print(f"{Colors.GREEN}Detailed report saved to: {filename}{Colors.RESET}")

def get_input_file():
    while True:
        file_name = input(f"{Colors.BLUE}Enter the path to your BTC addresses file (e.g., btc.txt): {Colors.RESET}").strip()
        if os.path.isfile(file_name):
            return file_name
        print(f"{Colors.RED}File not found: {file_name}. Please try again.{Colors.RESET}")

def get_transaction_limit():
    while True:
        limit = input(f"{Colors.BLUE}Enter the maximum number of transactions to fetch per address (0 for no limit): {Colors.RESET}").strip()
        try:
            limit = int(limit)
            if limit >= 0:
                return limit
            print(f"{Colors.RED}Please enter a positive number or 0 for no limit.{Colors.RESET}")
        except ValueError:
            print(f"{Colors.RED}Please enter a valid number.{Colors.RESET}")

def get_small_k_attempt_limit():
    while True:
        limit = input(f"{Colors.BLUE}Enter the maximum 'k' value to brute-force for Guessable Small K-Value (0 to disable brute-force for this vulnerability): {Colors.RESET}").strip()
        try:
            limit = int(limit)
            if limit >= 0:
                return limit
            print(f"{Colors.RED}Please enter a positive number or 0 to disable this check.{Colors.RESET}")
        except ValueError:
            print(f"{Colors.RED}Please enter a valid number.{Colors.RESET}")

def update_address_file(input_file_path, remaining_addresses):
    try:
        with open(input_file_path, 'w') as f:
            for address in remaining_addresses:
                f.write(address + '\n')
        print(f"{Colors.BRIGHT_BLACK}Updating '{input_file_path}' with {len(remaining_addresses)} remaining addresses.{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}Error updating address file: {e}{Colors.RESET}")

if __name__ == "__main__":
    original_addresses = []
    input_file_path = ""
    remaining_addresses_to_scan = []

    VULN_COUNTS = defaultdict(int)
    VULN_COUNTS['Reused Nonce'] = 0
    VULN_COUNTS['Weak RNG'] = 0
    VULN_COUNTS['Multi-Nonce Delta'] = 0 
    VULN_COUNTS['Low Order Points'] = 0
    VULN_COUNTS['K-Value Issues'] = 0
    VULN_COUNTS['K-Value Issues (Reused Nonce Derivation Failed Validation)'] = 0 
    VULN_COUNTS['Non-Canonical Signature'] = 0
    VULN_COUNTS['Guessable Small K-Value'] = 0 
    VULN_COUNTS['Weak RNG (Statistical)'] = 0
    VULN_COUNTS['Nonce Bias (Small R)'] = 0
    VULN_COUNTS['Nonce Bias (Leading Zeros in R)'] = 0
    VULN_COUNTS['Nonce Bias (Leading Zeros in S)'] = 0
    VULN_COUNTS['LLL Attack (Bias S/R)'] = 0 
    VULN_COUNTS['Fault Attack'] = 0 

    try:
        input_file_path = get_input_file()
        MAX_TRANSACTIONS = get_transaction_limit()
        GLOBAL_MAX_SMALL_K_ATTEMPT = get_small_k_attempt_limit() 
        
        with open(input_file_path, 'r') as f:
            original_addresses = [line.strip() for line in f if line.strip()]
        
        TOTAL_ADDRESSES = len(original_addresses)
        remaining_addresses_to_scan = list(original_addresses)
        
        while remaining_addresses_to_scan and not EXIT_FLAG:
            address_to_scan = remaining_addresses_to_scan[0]
            
            report = analyze_address(address_to_scan)
            
            remaining_addresses_to_scan.pop(0)
            
            update_address_file(input_file_path, remaining_addresses_to_scan)
            
            if EXIT_FLAG:
                break
        
        if not EXIT_FLAG:
            print(f"\n{Colors.BRIGHT_GREEN}Scan complete!{Colors.RESET}")
            final_percentage = (VULNERABLE_ADDRESSES/TOTAL_ADDRESSES*100) if TOTAL_ADDRESSES > 0 else 0
            final_vuln_color = Colors.GREEN if final_percentage == 0 else Colors.YELLOW if final_percentage < 10 else Colors.RED
            print(f"Final results: {final_vuln_color}{VULNERABLE_ADDRESSES}/{TOTAL_ADDRESSES} addresses have vulnerabilities{Colors.RESET}")
            print(f"\n{Colors.BRIGHT_BLUE}--- Vulnerability Type Summary ---{Colors.RESET}")
            print(f"{Colors.RED}🔴 Reused Nonce: {VULN_COUNTS['Reused Nonce']}{Colors.RESET}")
            print(f"{Colors.RED}🔴 Multi-Nonce Delta: {VULN_COUNTS['Multi-Nonce Delta']}{Colors.RESET}")
            print(f"{Colors.RED}🔴 Low Order Points: {VULN_COUNTS['Low Order Points']}{Colors.RESET}")
            print(f"{Colors.RED}� K-Value Issues: {VULN_COUNTS['K-Value Issues']}{Colors.RESET}")
            print(f"{Colors.RED}🔴 Guessable Small K-Value: {VULN_COUNTS['Guessable Small K-Value']}{Colors.RESET}")
            print(f"{Colors.RED}🔴 Fault Attack: {VULN_COUNTS['Fault Attack']}{Colors.RESET}")
            print(f"{Colors.ORANGE}🟠 LLL Attack (Bias S/R): {VULN_COUNTS['LLL Attack (Bias S/R)']}{Colors.RESET}")
            print(f"{Colors.YELLOW}🟡 Nonce Bias (Small R): {VULN_COUNTS['Nonce Bias (Small R)']}{Colors.RESET}")
            print(f"{Colors.YELLOW}🟡 Nonce Bias (Leading Zeros in R): {VULN_COUNTS['Nonce Bias (Leading Zeros in R)']}{Colors.RESET}")
            print(f"{Colors.YELLOW}🟡 Nonce Bias (Leading Zeros in S): {VULN_COUNTS['Nonce Bias (Leading Zeros in S)']}{Colors.RESET}")
            print(f"{Colors.YELLOW}🟡 K-Value Issues (Reused Nonce Derivation Failed Validation): {VULN_COUNTS['K-Value Issues (Reused Nonce Derivation Failed Validation)']}{Colors.RESET}")
            print(f"{Colors.GREEN}🟢 Non-Canonical Signature: {VULN_COUNTS['Non-Canonical Signature']}{Colors.RESET}")
            print(f"{Colors.GREEN}🟢 Weak RNG: {VULN_COUNTS['Weak RNG']}{Colors.RESET}")
            print(f"{Colors.GREEN}🟢 Weak RNG (Statistical): {VULN_COUNTS['Weak RNG (Statistical)']}{Colors.RESET}")
            if VULN_COUNTS['Guessable Small K-Value'] > 0:
                print(f"\n{Colors.BRIGHT_YELLOW}--- Special Advice: 'Guessable Small K-Value' Vulnerability Found! ---{Colors.RESET}")
                print(f"{Colors.YELLOW}Some private keys were recovered due to the use of extremely small 'k' (nonce) values.{Colors.RESET}")
                print(f"{Colors.YELLOW}The brute-force algorithm attempted 'k' up to your specified limit.{Colors.RESET}")
                print(f"{Colors.YELLOW}If you performed only a quick scan (small K-Value limit: {GLOBAL_MAX_SMALL_K_ATTEMPT}),{Colors.RESET}")
                print(f"{Colors.YELLOW}it's recommended to run a further scan with a higher limit{Colors.RESET}")
                print(f"{Colors.YELLOW}(e.g., 100,000 or 1,000,000) for potentially more key discoveries.{Colors.RESET}")
                print(f"{Colors.YELLOW}Be aware that this will require significantly longer processing time.{Colors.RESET}")
            
            print(f"\n{Colors.WHITE}All Vulnerable Addresses Found:{Colors.RESET}")
            for report in REPORTS:
                if report['vulnerabilities']:
                    print(f"{Colors.RED} {report['address']}{Colors.RESET}")
            print(f"\n{Colors.GREEN}All reports saved to the 'reports' folder.{Colors.RESET}")
            print(f"\n{Colors.BRIGHT_CYAN}Signature Scanner for Bitcoin Vulnerability{Colors.RESET}\n")
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Scan interrupted by user.{Colors.RESET}")
    except Exception as main_e:
        print(f"\n{Colors.RED}An unexpected error occurred: {main_e}{Colors.RESET}")
        import traceback
        traceback.print_exc() 
    finally:
        if input_file_path and os.path.exists(input_file_path):
            update_address_file(input_file_path, remaining_addresses_to_scan)
        sys.exit(0)