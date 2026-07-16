import socket
import json
import pickle
import random
import sys
import os
import time
import yaml
import struct
from datetime import datetime

# =======================================================================
# CONFIGURATION & GLOBAL MAPPING
# =======================================================================
TARGET_MODULE_NOMENCLATURE = {
    "f400": "ZGM (Central Gateway Module)", "f401": "BDC (Body Domain Controller)",
    "f410": "DME (Engine Control Unit)", "f412": "DME2 (Engine Control Unit 2)",
    "f418": "EGS (Transmission Control Unit)", "f419": "VTG (Transfer Case)",
    "f420": "VDM (Vehicle Dynamics Management)", "f429": "DSC (Dynamic Stability Control)", 
    "f444": "EPS (Electronic Power Steering)", "f443": "TPMS (Tire Pressure Monitoring System)", 
    "f406": "IHKA (HVAC)", "f407": "KOMBI (Instrument Cluster)", 
    "f408": "ACSM (Crash Safety)", "f436": "TEL (Telematics / Combox)",
    "f437": "AMP (Audio Amplifier)", "f438": "RAD (Radio/Nav)",
    "f439": "HU-H (Infotainment)", "f43a": "ASD (Active Sound Design)",
    "f440": "CAS (Car Access System)", "f456": "RVC (Rear View Camera)",
    "f45d": "PDC (Park Distance Control)", "f45e": "TRSVC (Top Rear Side View Camera)",
    "f461": "HUD (Head Up Display)", "f463": "CON (Controller)",
    "f46d": "FAS (Seat Module Driver)", "f472": "KAFAS (Camera Systems)",
    "f474": "FLA (High Beam Assistant)"
}

UDS_Request_Config = {}
UDS_Session_Results = {}

# =======================================================================
# LAYER 4: INNER PAYLOAD MULTI-TYPE DECRYPTER
# =======================================================================
def decode_inner_payload(raw_bytes):
    if not raw_bytes: return None
    ascii_clean = "".join([chr(b) if 32 <= b <= 126 else "." for b in raw_bytes])
    int8_array = list(raw_bytes)
    
    int16_array = []
    for i in range(0, len(raw_bytes) - 1, 2):
        val = int.from_bytes(raw_bytes[i:i+2], byteorder='big')
        int16_array.append(val)
        
    float32_array = []
    if len(raw_bytes) >= 4 and len(raw_bytes) % 4 == 0:
        for i in range(0, len(raw_bytes), 4):
            try:
                val = struct.unpack('>f', raw_bytes[i:i+4])[0]
                float32_array.append(round(val, 4)) 
            except: pass
            
    return {
        "hex": raw_bytes.hex(),
        "ascii_clean": ascii_clean,
        "int8_array": int8_array,
        "int16_array_big_endian": int16_array if int16_array else None,
        "float32_array": float32_array if float32_array else None
    }

# =======================================================================
# LAYER 3: STRUCTURAL DID PARSING ENGINE
# =======================================================================
def parse_did_payload(did_hex, raw_payload_bytes):
    if not did_hex or not raw_payload_bytes: return None
    did_upper = did_hex.upper()

    if did_upper == "F190": 
        try: return {"value": raw_payload_bytes.decode('ascii', errors='ignore').strip('\x00'), "type": "ascii", "description": "Vehicle Identification Number"}
        except: pass
    elif did_upper == "F18A": 
        try: return {"value": raw_payload_bytes.decode('ascii', errors='ignore').strip('\x00'), "type": "ascii", "description": "System Supplier Identifier"}
        except: pass
    elif did_upper == "F150": 
        try: return {"value": raw_payload_bytes.hex(), "type": "hex_string", "description": "Hardware Module Version"}
        except: pass
    elif did_upper in ["F18B", "F18C"]: 
        try:
            year = f"20{raw_payload_bytes[0]:02x}"
            month = f"{raw_payload_bytes[1]:02x}"
            day = f"{raw_payload_bytes[2]:02x}"
            desc = "ECU Manufacturing Date" if did_upper == "F18B" else "ECU Installation Date"
            return {"value": f"{year}-{month}-{day}", "type": "date_bcd", "description": desc}
        except: pass

    return {"value": raw_payload_bytes.hex(), "type": "hex", "description": "Unmapped DID Payload"}

# =======================================================================
# LAYER 2: UDS PROTOCOL DECODER
# =======================================================================
def decode_uds_message(uds_data, source, target):
    if not uds_data: return {"error": "Empty UDS payload"}
    sid = uds_data[0]
    sid_map = {
        0x10: "Diagnostic Session Control", 0x11: "ECU Reset", 0x19: "Read DTC Information",
        0x22: "Read Data By Identifier", 0x27: "Security Access", 0x2E: "Write Data By Identifier",
        0x31: "Routine Control", 0x3E: "Tester Present", 0x62: "Read Data By Identifier (Response)",
        0x69: "Security Access (Response)", 0x7E: "Tester Present (Response)", 0x7F: "Negative Response"
    }
    return {
        "source": hex(source), "target": hex(target), "service_id": hex(sid),
        "service_name": sid_map.get(sid, "Unknown Service"),
        "payload": uds_data[1:].hex() if len(uds_data) > 1 else ""
    }

# =======================================================================
# LAYER 1: DUAL-STACK ENET/DOIP PACKET DECODER
# =======================================================================
def decode_enet_packet(raw_hex_str):
    try:
        packet_bytes = bytes.fromhex(raw_hex_str)
        if len(packet_bytes) < 4: return {"error": "Packet too short"}
        
        if packet_bytes[0] == 0x02 and packet_bytes[1] == 0xFD:
            payload_type = int.from_bytes(packet_bytes[2:4], byteorder='big')
            if payload_type == 0x8002: return {"protocol": "ISO_13400", "type": "DoIP_ACK"}
            if payload_type != 0x8001: return {"error": f"Not a diagnostic message (Type: {hex(payload_type)})"}
            
            src_addr = int.from_bytes(packet_bytes[8:10], byteorder='big')
            tgt_addr = int.from_bytes(packet_bytes[10:12], byteorder='big')
            uds_data = packet_bytes[12:]
            
            res = decode_uds_message(uds_data, src_addr, tgt_addr)
            res["raw_message"] = raw_hex_str
            res["protocol"] = "ISO_13400"
            return res
            
        elif packet_bytes[0] == 0x00 and packet_bytes[1] == 0x00:
            payload_length = int.from_bytes(packet_bytes[0:4], byteorder='big')
            tgt_addr = int.from_bytes(packet_bytes[6:8], byteorder='big')
            
            packet_type = int.from_bytes(packet_bytes[4:6], byteorder='big')
            if packet_type == 2: return {"protocol": "BMW_ENET", "type": "Gateway_ACK"}
            
            uds_data = packet_bytes[8: 6 + payload_length]
            res = decode_uds_message(uds_data, 0xf4, tgt_addr)
            res["raw_message"] = raw_hex_str
            res["protocol"] = "BMW_ENET"
            return res
            
        return {"error": "Unknown protocol signature"}
    except Exception as e: return {"error": str(e)}

# =======================================================================
# IMMUTABLE DICTIONARY GENERATOR
# =======================================================================
def load_request_config(yaml_path, target_platform="BMW_MINI_U006"):
    global UDS_Request_Config
    UDS_Request_Config.clear() 
    
    if not os.path.exists(yaml_path):
        print(f"[-] Error: {yaml_path} not found.")
        sys.exit(1)
        
    with open(yaml_path, 'r') as f:
        raw_data = yaml.safe_load(f).get(target_platform, [])
        
    lines = [str(line).lstrip('-').strip() for line in (raw_data.split() if isinstance(raw_data, str) else raw_data)]

    for line in lines:
        if not line: continue
        parts = line.split(',')
        payload_hex = parts[0]
        if len(payload_hex) < 16: continue 
        
        target = payload_hex[12:16]
        msg_hex = payload_hex[16:]
        
        full_payload_bytes = bytes.fromhex(payload_hex)
        req_uds = full_payload_bytes[12:] if full_payload_bytes[0] == 0x02 else full_payload_bytes[8:]
        is_auth = "2908" in msg_hex
        
        if target not in UDS_Request_Config:
            UDS_Request_Config[target] = {"nomenclature": TARGET_MODULE_NOMENCLATURE.get(target, f"UNKNOWN_({target})"), "messages": {}}
            
        UDS_Request_Config[target]["messages"][msg_hex] = {
            "full_payload_hex": payload_hex,
            "full_payload_bytes": full_payload_bytes,
            "req_uds": req_uds,
            "is_auth": is_auth,
            "expects_type_2_ack": is_auth, 
            "expected_sid": req_uds[0] + 0x40,
            "heartbeat": "hearthbeat" in parts or "heartbeat" in parts
        }

    # Ensure Auth routines execute first in the dictionary order
    auth_tgt = next((t for t, d in UDS_Request_Config.items() if any(m["is_auth"] for m in d["messages"].values())), None)
    if auth_tgt:
        msgs = UDS_Request_Config[auth_tgt]["messages"]
        auth_msg = next(k for k, v in msgs.items() if v["is_auth"])
        UDS_Request_Config[auth_tgt]["messages"] = {auth_msg: msgs.pop(auth_msg), **msgs}
        reordered_dict = {auth_tgt: UDS_Request_Config.pop(auth_tgt), **UDS_Request_Config}
        UDS_Request_Config.clear()
        UDS_Request_Config.update(reordered_dict)
            
    print(f"[+] Loaded configuration for {len(UDS_Request_Config)} target modules.")


# =======================================================================
# MAIN ENGINE CLASS
# =======================================================================
class MINI_DoIP_UDS:
    def __init__(self):
        self.car_ip = None
        self.last_activity = time.time()
        self.tcp_buffer = bytearray() 
        
    def _get_apipa_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('169.254.255.255', 1))
            ip = s.getsockname()[0]
        except Exception: ip = '169.254.0.10' 
        finally: s.close()
        return ip
        
    def safe_bind_doip_socket(self, sock):
        local_ip = self._get_apipa_ip()
        for _ in range(100):
            port = random.randint(49152, 65535)
            try:
                sock.bind((local_ip, port))
                return local_ip, port
            except (PermissionError, OSError):
                try:
                    sock.bind(('0.0.0.0', port))
                    return '0.0.0.0', port
                except (PermissionError, OSError): continue
        sys.exit(1)

    def DOIP_discovery_function(self, broadcast_ip='169.254.255.255', port=6811):
        print(f"[*] Binding UDP Socket for Discovery...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        bound_ip, bound_port = self.safe_bind_doip_socket(sock)
        sock.settimeout(5.0)
        discovery_payload = bytes.fromhex("000000000011")
        try:
            sock.sendto(discovery_payload, (broadcast_ip, port))
            data, addr = sock.recvfrom(1024)
            if len(data) == 56:
                print(f"    [+] Car discovered at {addr[0]}")
                self.car_ip = addr[0]
            else: sys.exit(1)
        except socket.timeout:
            print("[-] Discovery timed out.")
            sys.exit(1)
        finally: sock.close()

    # ===================================================================
    # ENGINE SUBSYSTEMS & REFACTORED HELPERS
    # ===================================================================
    def _initialize_session_tracker(self):
        global UDS_Request_Config
        global UDS_Session_Results
        UDS_Session_Results.clear()
        for target, config in UDS_Request_Config.items():
            UDS_Session_Results[target] = {"nomenclature": config["nomenclature"], "results": {}}
            for msg_hex in config["messages"]:
                UDS_Session_Results[target]["results"][msg_hex] = {
                    "status": "PENDING", "raw": None, "encoded": None, 
                    "inner_payload": None, "parsed": None
                }

    def reconnect_session(self, port=6801):
        """Safely tears down the current TCP socket and spins up a fresh APIPA session."""
        try: self.sock.shutdown(socket.SHUT_RDWR)
        except OSError: pass 
        finally: 
            if hasattr(self, 'sock') and self.sock: 
                self.sock.close()
                
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        local_ip, local_port = self.safe_bind_doip_socket(self.sock)
        self.sock.settimeout(5.0)
        self.sock.connect((self.car_ip, port))
        return local_port

    def _evaluate_nrc(self, uds_data):
        """Safely evaluates a UDS Negative Response Code (NRC)."""
        if not uds_data or len(uds_data) < 3 or uds_data[0] != 0x7f:
            return None
        if uds_data[2] == 0x21: return "BUSY"
        if uds_data[2] == 0x78: return "PENDING"
        return "HARD_ERROR"

    def _validate_and_slice_echo(self, req_uds, uds_data, expected_sid):
        """Validates DID/RID matches and slices inner payload."""
        if not uds_data or uds_data[0] != expected_sid:
            return False, None
            
        request_sid = req_uds[0]
        
        if request_sid in [0x22, 0x2E]:
            if len(uds_data) >= 3 and len(req_uds) >= 3:
                if uds_data[1:3] != req_uds[1:3]: return False, None
            return True, uds_data[3:]
            
        elif request_sid == 0x31:
            if len(uds_data) >= 4 and len(req_uds) >= 4:
                if uds_data[1:4] != req_uds[1:4]: return False, None
            return True, uds_data[4:]
            
        elif request_sid in [0x11, 0x3E]:
            if len(uds_data) >= 2 and len(req_uds) >= 2:
                if uds_data[1] != req_uds[1]: return False, None
            return True, uds_data[2:]
            
        return True, uds_data[1:] 

    def flush_os_socket(self, sock):
        sock.setblocking(False) 
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk: break
        except (BlockingIOError, OSError): pass 
        finally: sock.settimeout(5.0) 
        self.tcp_buffer.clear() 

    def stream_doip_response(self, sock, timeout=5.0, allow_type_2=False):
        sock.settimeout(timeout)
        start_time = time.time()
        while True:
            while len(self.tcp_buffer) >= 4:
                if self.tcp_buffer[0] == 0x02 and self.tcp_buffer[1] == 0xFD:
                    if len(self.tcp_buffer) < 8: break
                    payload_type = int.from_bytes(self.tcp_buffer[2:4], byteorder='big')
                    payload_length = int.from_bytes(self.tcp_buffer[4:8], byteorder='big')
                    full_size = 8 + payload_length
                    
                    if len(self.tcp_buffer) < full_size: break
                    packet = self.tcp_buffer[:full_size]
                    self.tcp_buffer = self.tcp_buffer[full_size:]
                    
                    if payload_type == 0x8002: continue 
                    elif payload_type == 0x8001: return {"packet": packet, "uds": packet[12:], "type": 1}
                    else: continue

                elif self.tcp_buffer[0] == 0x00 and self.tcp_buffer[1] == 0x00:
                    if len(self.tcp_buffer) < 6: break
                    payload_length = int.from_bytes(self.tcp_buffer[0:4], byteorder='big')
                    full_size = 6 + payload_length
                    
                    if len(self.tcp_buffer) < full_size: break
                    packet = self.tcp_buffer[:full_size]
                    self.tcp_buffer = self.tcp_buffer[full_size:]
                    
                    packet_type = int.from_bytes(packet[4:6], byteorder='big')
                    
                    if packet_type == 1: return {"packet": packet, "uds": packet[8:], "type": 1}
                    elif packet_type == 2 and allow_type_2: return {"packet": packet, "uds": packet[6:], "type": 2}
                    else: continue
                else:
                    self.tcp_buffer.pop(0)

            if time.time() - start_time > timeout: raise TimeoutError("Socket timed out.")
            try:
                chunk = sock.recv(4096)
                if not chunk: raise ConnectionResetError("Connection closed by peer.")
                self.tcp_buffer.extend(chunk)
            except socket.timeout: raise TimeoutError("Socket recv timeout.")

    def send_tester_present(self, sock, target_unit):
        full_target = f"f4{target_unit}"
        heartbeat_hex = f"000000040001{full_target}3e80"
        try:
            sock.sendall(bytes.fromhex(heartbeat_hex))
            print(f"        [+] Heartbeat (3E 80) sent to {full_target}.")
        except Exception as e: print(f"        [-] Failed to send Heartbeat: {e}")

    # ===================================================================
    # ISOLATED EXECUTION BRANCH: Authentication
    # ===================================================================
    def _execute_auth_sequence(self, target, msg_hex, config, session_entry, port):
        print("    [!] 29 08 octets detected. Authenticating...")
        self.flush_os_socket(self.sock) 
        self.sock.sendall(config["full_payload_bytes"])
        
        max_auth_loops = 15
        for _ in range(max_auth_loops):
            try: response_dict = self.stream_doip_response(self.sock, timeout=12.0, allow_type_2=config["expects_type_2_ack"])
            except TimeoutError:
                print("        [-] Socket timed out waiting for Auth Response.")
                session_entry["status"] = "FAILED"
                break
                
            uds_data = response_dict["uds"]
            response_packet = response_dict["packet"]
            response_hex = uds_data.hex()
            
            if response_dict.get("type", 1) == 2:
                if "2908" in response_hex:
                    print("        [+] Gateway trapped and ACK'd 29 08 at Transport Layer. Auth Granted!")
                    session_entry["status"] = "SUCCESS"
                else:
                    print(f"        [-] Unexpected Type 2 response: {response_hex}")
                    session_entry["status"] = "FAILED"
            else:
                if not uds_data: continue
                nrc_status = self._evaluate_nrc(uds_data)
                
                if nrc_status == "PENDING":
                    print("        [!] Auth Response Pending (NRC 78). ECU is calculating...")
                    continue
                    
                if len(uds_data) >= 2 and uds_data[0] == 0x69:
                    if "2909" in response_hex or "6909" in response_hex or uds_data[1] == 0x09:
                        print("        [!] SEED RECEIVED: ECU demands 29 09 Crypto Job.")
                        session_entry["status"] = "AUTH_PENDING_CRYPTO"
                    elif uds_data[1] == 0x08 or "2908" in response_hex or "6908" in response_hex:
                        print("        [+] Auth accepted by ECU (No seed required).")
                        session_entry["status"] = "SUCCESS"
                    else:
                        print(f"        [?] Auth accepted but unknown subfunction: {response_hex}")
                        session_entry["status"] = "SUCCESS"
                else:
                    print(f"        [-] Auth REJECTED by ECU! Response: {response_packet.hex()}")
                    session_entry["status"] = "FAILED"
                    
            session_entry["raw"] = response_packet.hex()
            session_entry["encoded"] = decode_enet_packet(response_packet.hex())
            break 
        
        print("    [!] Auth cycle complete. Gracefully tearing down session (ISTA Behavior).")
        new_port = self.reconnect_session(port)
        print(f"    [+] New session established for data sweep (Local Sender Port: {new_port}).")

    # ===================================================================
    # ISOLATED EXECUTION BRANCH: Main Data Sweep
    # ===================================================================
    def _execute_main_sweep(self, target, msg_hex, config, session_entry):
        max_retries = 20
        request_needs_sending = True
        
        for attempt in range(max_retries):
            if request_needs_sending:
                self.flush_os_socket(self.sock) 
                self.sock.sendall(config["full_payload_bytes"])
                request_needs_sending = False 
            
            try: response_dict = self.stream_doip_response(self.sock)
            except TimeoutError:
                print("        [-] Socket timed out waiting for ECU.")
                session_entry["status"] = "TIMEOUT"
                break
                
            uds_data = response_dict["uds"]
            response_packet = response_dict["packet"]
            if not uds_data: continue
            
            nrc_status = self._evaluate_nrc(uds_data)
            if nrc_status == "BUSY":
                if attempt < (max_retries - 1):
                    print(f"        [!] ECU Busy (NRC 21). Backing off... ({attempt + 1}/{max_retries})")
                    time.sleep(0.25)
                    request_needs_sending = True 
                    continue
                else:
                    print(f"        [-] Retries Exhausted. Marking BUSY_DEFERRED.")
                    session_entry["status"] = "BUSY_DEFERRED"
                    break
            elif nrc_status == "PENDING":
                print(f"        [!] Response Pending (NRC 78). Waiting...")
                continue
            elif nrc_status == "HARD_ERROR":
                print(f"        [-] Hard UDS Error: {response_packet.hex()}")
                session_entry["status"] = "FAILED"
                session_entry["raw"] = response_packet.hex()
                session_entry["encoded"] = decode_enet_packet(response_packet.hex())
                break
            
            is_flawless, inner_bytes = self._validate_and_slice_echo(config["req_uds"], uds_data, config["expected_sid"])
            if not is_flawless:
                if uds_data[0] == config["expected_sid"]:
                    print(f"        [!] Stray response detected (Mismatched DID/RID). Discarding...")
                continue 

            print(f"        [+] SUCCESS! Flawless Data received.")
            session_entry["status"] = "SUCCESS"
            session_entry["raw"] = response_packet.hex()
            session_entry["encoded"] = decode_enet_packet(response_packet.hex())
            session_entry["inner_payload"] = decode_inner_payload(inner_bytes)
            
            if config["expected_sid"] == 0x62:
                did_hex = uds_data[1:3].hex()
                session_entry["parsed"] = parse_did_payload(did_hex, uds_data[3:])
            break 

    # ===================================================================
    # THE ORCHESTRATOR
    # ===================================================================
    def DOIP_message_handler(self, port=6801):
        global UDS_Request_Config
        global UDS_Session_Results
        
        if not self.car_ip: return
        self._initialize_session_tracker()

        print(f"\n[*] Establishing Sequential DOIP TCP session to {self.car_ip}:{port}")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        local_ip, local_port = self.safe_bind_doip_socket(self.sock)
        print(f"[*] Local Sender Bound to: {local_ip}:{local_port}")
        self.sock.settimeout(5.0)
        self.sock.connect((self.car_ip, port))

        for target, config_data in UDS_Request_Config.items():
            print(f"\n[*] Sweeping Target Unit: {target} ({config_data['nomenclature']})")

            for msg_hex, config in config_data["messages"].items():
                session_entry = UDS_Session_Results[target]["results"][msg_hex]
                print(f"    [>] Sending UDS: {msg_hex}")
                
                if config["heartbeat"]:
                    self.send_tester_present(self.sock, target[2:])
                    time.sleep(0.05) 
                
                try:
                    if config["is_auth"]:
                        self._execute_auth_sequence(target, msg_hex, config, session_entry, port)
                    else:
                        self._execute_main_sweep(target, msg_hex, config, session_entry)
                except Exception as e:
                    print(f"    [-] Error processing {msg_hex}: {e}")
                    session_entry["status"] = "FAILED"
                    
        self.busy_repeat_request_tracker(self.sock)

        print(f"\n[*] Sweeps completed. Terminating main DOIP TCP session.")
        try: self.sock.shutdown(socket.SHUT_RDWR)
        except OSError: pass 
        finally: self.sock.close()

    # ===================================================================
    # ISOLATED EXECUTION BRANCH: Mop-Up Protocol
    # ===================================================================
    def busy_repeat_request_tracker(self, sock):
        global UDS_Session_Results
        global UDS_Request_Config
        
        deferred_count = sum(1 for target in UDS_Session_Results.values() for session in target["results"].values() if session["status"] == "BUSY_DEFERRED")
        if deferred_count == 0: return 

        print(f"\n=======================================================")
        print(f"[*] INITIATING BUSY REPEAT REQUEST TRACKER")
        print(f"[*] Re-engaging {deferred_count} skipped payloads...")
        print(f"=======================================================\n")
        time.sleep(1.0) 

        for target, session_data in UDS_Session_Results.items():
            for msg_hex, session_entry in session_data["results"].items():
                if session_entry["status"] == "BUSY_DEFERRED":
                    config = UDS_Request_Config[target]["messages"][msg_hex]
                    print(f"    [>] Final Assault: {target} -> {msg_hex}")
                    self.send_tester_present(sock, target[2:])
                    time.sleep(0.1)
                    
                    try:
                        self.flush_os_socket(sock) 
                        sock.sendall(config["full_payload_bytes"])
                        
                        for _ in range(15): 
                            try: response_dict = self.stream_doip_response(sock)
                            except TimeoutError:
                                print("        [-] Socket timed out during final assault.")
                                session_entry["status"] = "TIMEOUT"
                                break
                                
                            uds_data = response_dict["uds"]
                            response_packet = response_dict["packet"]
                            if not uds_data: continue
                            
                            nrc_status = self._evaluate_nrc(uds_data)
                            if nrc_status == "PENDING":
                                print(f"        [!] Finally Accepted (NRC 78). Waiting...")
                                continue 
                            elif nrc_status == "BUSY":
                                print(f"        [-] Still locked (NRC 21). Abandoning.")
                                session_entry["status"] = "FAILED"
                                break 
                            
                            is_flawless, inner_bytes = self._validate_and_slice_echo(config["req_uds"], uds_data, config["expected_sid"])
                            if not is_flawless: continue

                            print(f"        [+] SUCCESS! Data recovered on final pass.")
                            session_entry["status"] = "SUCCESS"
                            session_entry["raw"] = response_packet.hex()
                            session_entry["encoded"] = decode_enet_packet(response_packet.hex())
                            session_entry["inner_payload"] = decode_inner_payload(inner_bytes)
                            
                            if config["expected_sid"] == 0x62:
                                did_hex = uds_data[1:3].hex()
                                session_entry["parsed"] = parse_did_payload(did_hex, uds_data[3:])
                            break 
                                
                    except Exception as e:
                        print(f"        [-] Error during final execution of {msg_hex}: {e}")
                        session_entry["status"] = "FAILED"
        print(f"[*] Busy Repeat Request Tracker completed.\n")
    
    def session_save_function(self):
        global UDS_Session_Results
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            filename = f"Scan_Result_{timestamp}.json"
            with open(filename, "w") as jf: 
                json.dump(UDS_Session_Results, jf, indent=4)
            print(f"[+] Saved Clean Session JSON successfully to {filename}.")
        except Exception as e: print(f"[-] Failed to save outputs: {e}")

def execution_loop():
    yaml_path = "UDS_payloads.yaml" 
    print("[*] Generating Immutable Target Dictionary...")
    load_request_config(yaml_path)
    
    doip_client = MINI_DoIP_UDS()
    print("[*] Initiating DOIP Discovery...")
    doip_client.DOIP_discovery_function()
    
    print("[*] Beginning DOIP Message Sweeps...")
    doip_client.DOIP_message_handler(port=6801)
    
    print("[*] Saving Sessions...")
    doip_client.session_save_function()
    print("[*] Execution Loop Completed.")

if __name__ == "__main__":
    execution_loop()