#!/usr/bin/env python3
import socket
import struct
import sys
import urllib.parse
import re
from enum import Enum

class Protocol(Enum):
    TCP = 1
    UDP = 2
    ANY = 3

class ApiType(Enum):
    TEXT = 1
    BINARY = 2

# Binary protocol constants
CALC_MESSAGE_TYPE = 22
CALC_PROTOCOL_TYPE = 1
ERROR_MESSAGE_TYPE = 2
PROTOCOL_ID = 17
MAJOR_VERSION = 1
MINOR_VERSION = 0

# Binary message structures
class CalcMessage:
    def __init__(self, msg_type, message, protocol, major_version, minor_version):
        self.type = msg_type
        self.message = message
        self.protocol = protocol
        self.major_version = major_version
        self.minor_version = minor_version

class CalcProtocol:
    def __init__(self, msg_type, major_version, minor_version, id, arith, in_value1, in_value2, in_result):
        self.type = msg_type
        self.major_version = major_version
        self.minor_version = minor_version
        self.id = id
        self.arith = arith
        self.in_value1 = in_value1
        self.in_value2 = in_value2
        self.in_result = in_result

def parse_url(url):
    try:
        # Parse the URL
        parsed = urllib.parse.urlparse(url)
        protocol_str = parsed.scheme.upper()
        api_str = parsed.path.lstrip('/').lower()
        
        # Validate protocol
        if protocol_str not in ['TCP', 'UDP', 'ANY']:
            raise ValueError(f"Invalid protocol: {protocol_str}")
            
        # Validate API type
        if api_str not in ['text', 'binary']:
            raise ValueError(f"Invalid API type: {api_str}")
            
        # Get host and port
        host = parsed.hostname
        port = parsed.port
        
        if not host:
            raise ValueError("Missing host")
        if not port:
            raise ValueError("Missing port")
            
        # Convert to enums
        protocol = Protocol[protocol_str]
        api_type = ApiType.TEXT if api_str == 'text' else ApiType.BINARY
        
        return protocol, host, port, api_type
        
    except Exception as e:
        print(f"ERROR: Invalid URL format - {e}", file=sys.stderr)
        sys.exit(1)

def resolve_host(host, port, protocol):
    try:
        # Determine socket type
        if protocol == Protocol.TCP:
            sock_type = socket.SOCK_STREAM
        else:
            sock_type = socket.SOCK_DGRAM
            
        # Get address info
        addrinfos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, sock_type)
        if not addrinfos:
            raise ValueError("No address info found")
            
        return addrinfos[0]  # Return the first address info
        
    except Exception as e:
        print(f"ERROR: RESOLVE ISSUE - {e}", file=sys.stderr)
        sys.exit(1)

def perform_text_tcp(host, port):
    try:
        # Resolve host
        family, socktype, proto, canonname, sockaddr = resolve_host(host, port, Protocol.TCP)
        
        # Create socket and connect
        with socket.socket(family, socktype, proto) as sock:
            sock.connect(sockaddr)
            
            # Read server protocols
            protocols = []
            while True:
                data = sock.recv(1024)
                if not data:
                    break
                    
                # Split by newline
                lines = data.decode('ascii').split('\n')
                for line in lines:
                    if line.strip() == '':
                        break
                    protocols.append(line.strip())
                else:
                    continue
                break
                
            # Check if TEXT TCP 1.1 is supported
            if "TEXT TCP 1.1" not in protocols:
                print("ERROR: MISSMATCH PROTOCOL", file=sys.stderr)
                return False
                
            # Send acceptance
            sock.sendall(b"TEXT TCP 1.1 OK\n")
            
            # Read assignment
            assignment = b''
            while True:
                data = sock.recv(1)
                if not data or data == b'\n':
                    break
                assignment += data
                
            assignment = assignment.decode('ascii').strip()
            print(f"ASSIGNMENT: {assignment}")
            
            # Parse and calculate
            parts = assignment.split()
            if len(parts) != 3:
                print("ERROR: Invalid assignment format", file=sys.stderr)
                return False
                
            op, val1_str, val2_str = parts
            
            try:
                val1 = int(val1_str)
                val2 = int(val2_str)
            except ValueError:
                print("ERROR: Invalid number format", file=sys.stderr)
                return False
                
            if op == 'add':
                result = val1 + val2
            elif op == 'sub':
                result = val1 - val2
            elif op == 'mul':
                result = val1 * val2
            elif op == 'div':
                if val2 == 0:
                    print("ERROR: Division by zero", file=sys.stderr)
                    return False
                result = val1 // val2  # Integer division
            else:
                print(f"ERROR: Unknown operation: {op}", file=sys.stderr)
                return False
                
            # Send result
            sock.sendall(f"{result}\n".encode('ascii'))
            
            # Read response
            response = b''
            while True:
                data = sock.recv(1)
                if not data or data == b'\n':
                    break
                response += data
                
            response = response.decode('ascii').strip()
            if response == 'OK':
                print("OK")
                return True
            else:
                print("ERROR")
                return False
                
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return False

def perform_binary_tcp(host, port):
    try:
        # Resolve host
        family, socktype, proto, canonname, sockaddr = resolve_host(host, port, Protocol.TCP)
        
        # Create socket and connect
        with socket.socket(family, socktype, proto) as sock:
            sock.connect(sockaddr)
            
            # Read server protocols
            protocols = []
            while True:
                data = sock.recv(1024)
                if not data:
                    break
                    
                # Split by newline
                lines = data.decode('ascii').split('\n')
                for line in lines:
                    if line.strip() == '':
                        break
                    protocols.append(line.strip())
                else:
                    continue
                break
                
            # Check if BINARY TCP 1.1 is supported
            if "BINARY TCP 1.1" not in protocols:
                print("ERROR: MISSMATCH PROTOCOL", file=sys.stderr)
                return False
                
            # Send acceptance
            sock.sendall(b"BINARY TCP 1.1 OK\n")
            
            # Read binary protocol message
            data = b''
            while len(data) < 20:  # Size of CalcProtocol structure
                chunk = sock.recv(20 - len(data))
                if not chunk:
                    break
                data += chunk
                
            if len(data) != 20:
                print("ERROR: Incorrect binary message size", file=sys.stderr)
                return False
                
            # Unpack the binary data
            # Structure: type (H), major_version (H), minor_version (H), id (I), arith (I), in_value1 (i), in_value2 (i)
            unpacked = struct.unpack('!HHHIIii', data)
            msg_type, major, minor, id_val, arith, in_value1, in_value2 = unpacked
            
            if msg_type != CALC_PROTOCOL_TYPE:
                print("ERROR: Invalid message type", file=sys.stderr)
                return False
                
            # Calculate result
            if arith == 0:  # add
                result = in_value1 + in_value2
            elif arith == 1:  # sub
                result = in_value1 - in_value2
            elif arith == 2:  # mul
                result = in_value1 * in_value2
            elif arith == 3:  # div
                if in_value2 == 0:
                    print("ERROR: Division by zero", file=sys.stderr)
                    return False
                result = in_value1 // in_value2
            else:
                print(f"ERROR: Unknown arithmetic operation: {arith}", file=sys.stderr)
                return False
                
            # Pack and send response
            response = struct.pack('!HHHIIiii', CALC_PROTOCOL_TYPE, MAJOR_VERSION, MINOR_VERSION, 
                                  id_val, arith, in_value1, in_value2, result)
            sock.sendall(response)
            
            # Read server response
            response_data = sock.recv(1024)
            if not response_data:
                print("ERROR: No response from server", file=sys.stderr)
                return False
                
            if response_data.decode('ascii').strip() == 'OK':
                print("OK")
                return True
            else:
                print("ERROR")
                return False
                
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return False

def perform_text_udp(host, port):
    try:
        # Resolve host
        family, socktype, proto, canonname, sockaddr = resolve_host(host, port, Protocol.UDP)
        
        # Create socket
        with socket.socket(family, socktype, proto) as sock:
            sock.settimeout(2.0)  # 2 second timeout
            
            # Send initial message
            sock.sendto(b"TEXT UDP 1.1\n", sockaddr)
            
            # Receive response
            data, addr = sock.recvfrom(1024)
            assignment = data.decode('ascii').strip()
            print(f"ASSIGNMENT: {assignment}")
            
            # Parse and calculate
            parts = assignment.split()
            if len(parts) != 3:
                print("ERROR: Invalid assignment format", file=sys.stderr)
                return False
                
            op, val1_str, val2_str = parts
            
            try:
                val1 = int(val1_str)
                val2 = int(val2_str)
            except ValueError:
                print("ERROR: Invalid number format", file=sys.stderr)
                return False
                
            if op == 'add':
                result = val1 + val2
            elif op == 'sub':
                result = val1 - val2
            elif op == 'mul':
                result = val1 * val2
            elif op == 'div':
                if val2 == 0:
                    print("ERROR: Division by zero", file=sys.stderr)
                    return False
                result = val1 // val2  # Integer division
            else:
                print(f"ERROR: Unknown operation: {op}", file=sys.stderr)
                return False
                
            # Send result
            sock.sendto(f"{result}\n".encode('ascii'), addr)
            
            # Receive final response
            data, addr = sock.recvfrom(1024)
            response = data.decode('ascii').strip()
            if response == 'OK':
                print("OK")
                return True
            else:
                print("ERROR")
                return False
                
    except socket.timeout:
        print("ERROR: MESSAGE LOST (TIMEOUT)", file=sys.stderr)
        return False
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return False

def perform_binary_udp(host, port):
    try:
        # Resolve host
        family, socktype, proto, canonname, sockaddr = resolve_host(host, port, Protocol.UDP)
        
        # Create socket
        with socket.socket(family, socktype, proto) as sock:
            sock.settimeout(2.0)  # 2 second timeout
            
            # Create and send initial message
            init_msg = struct.pack('!HHHHH', CALC_MESSAGE_TYPE, 0, PROTOCOL_ID, MAJOR_VERSION, MINOR_VERSION)
            sock.sendto(init_msg, sockaddr)
            
            # Receive response
            data, addr = sock.recvfrom(1024)
            
            if len(data) == 10:  # Error message size
                # Check if it's an error message
                msg_type, message, protocol, major, minor = struct.unpack('!HHHHH', data)
                if msg_type == ERROR_MESSAGE_TYPE and message == 2:
                    print("ERROR: Server does not support the protocol", file=sys.stderr)
                    return False
                    
            elif len(data) == 20:  # CalcProtocol message size
                # Unpack the binary data
                unpacked = struct.unpack('!HHHIIii', data)
                msg_type, major, minor, id_val, arith, in_value1, in_value2 = unpacked
                
                if msg_type != CALC_PROTOCOL_TYPE:
                    print("ERROR: Invalid message type", file=sys.stderr)
                    return False
                    
                # Calculate result
                if arith == 0:  # add
                    result = in_value1 + in_value2
                elif arith == 1:  # sub
                    result = in_value1 - in_value2
                elif arith == 2:  # mul
                    result = in_value1 * in_value2
                elif arith == 3:  # div
                    if in_value2 == 0:
                        print("ERROR: Division by zero", file=sys.stderr)
                        return False
                    result = in_value1 // in_value2
                else:
                    print(f"ERROR: Unknown arithmetic operation: {arith}", file=sys.stderr)
                    return False
                    
                # Pack and send response
                response = struct.pack('!HHHIIiii', CALC_PROTOCOL_TYPE, MAJOR_VERSION, MINOR_VERSION, 
                                      id_val, arith, in_value1, in_value2, result)
                sock.sendto(response, addr)
                
                # Receive final response
                data, addr = sock.recvfrom(1024)
                
                if len(data) == 10:  # Response message size
                    msg_type, message, protocol, major, minor = struct.unpack('!HHHHH', data)
                    if msg_type == CALC_MESSAGE_TYPE and message == 1:
                        print("OK")
                        return True
                    else:
                        print("ERROR")
                        return False
                else:
                    print("ERROR: Invalid response size", file=sys.stderr)
                    return False
            else:
                print("ERROR: Invalid message size", file=sys.stderr)
                return False
                
    except socket.timeout:
        print("ERROR: MESSAGE LOST (TIMEOUT)", file=sys.stderr)
        return False
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return False

def main():
    if len(sys.argv) != 2:
        print("Usage: client PROTOCOL://host:port/api")
        print("Example: client TCP://alice.nplab.bth.se:5000/text")
        sys.exit(1)
        
    url = sys.argv[1]
    protocol, host, port, api_type = parse_url(url)
    
    print(f"Protocol: {protocol.name}, Host: {host}, Port: {port}, API: {api_type.name}")
    
    success = False
    
    # Handle ANY protocol by trying both TCP and UDP
    if protocol == Protocol.ANY:
        # Try TCP first
        if api_type == ApiType.TEXT:
            success = perform_text_tcp(host, port)
        else:
            success = perform_binary_tcp(host, port)
            
        # If TCP failed, try UDP
        if not success:
            print("TCP failed, trying UDP...")
            if api_type == ApiType.TEXT:
                success = perform_text_udp(host, port)
            else:
                success = perform_binary_udp(host, port)
    else:
        # Use the specified protocol
        if protocol == Protocol.TCP:
            if api_type == ApiType.TEXT:
                success = perform_text_tcp(host, port)
            else:
                success = perform_binary_tcp(host, port)
        else:  # UDP
            if api_type == ApiType.TEXT:
                success = perform_text_udp(host, port)
            else:
                success = perform_binary_udp(host, port)
                
    if success:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()