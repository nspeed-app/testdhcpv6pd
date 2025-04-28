#!/usr/bin/env python3
# Copyright 2023 Michael Johnson
# 2024 Claude AI (Transformation)
# 2025 Gemini AI (Transformation)
# Copyright 2025 Jean-Francois Giorgi (AI Correction)
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import struct
import sys
import uuid
import io # Needed for BytesIO
import datetime # Needed for timestamp conversion

# --- DUID Definitions ---
# Based on RFC 8415 Section 11
duid_types = {
    1: 'DUID-LLT - Link-layer address plus time',
    2: 'DUID-EN - Vendor-assigned unique ID based on Enterprise Number',
    3: 'DUID-LL - Link-layer address',
    4: 'DUID-UUID - Universally Unique IDentifier'
}
# Based on RFC 8415 Section 23.3 (Hardware Types) - only Ethernet common
hw_types = {
    1: 'Ethernet'
    # Add other hardware types here if needed (e.g., 6: 'IEEE 802 Networks')
}

# --- Argument Parsing ---
if len(sys.argv) != 2:
    print("Usage: decode_duid.py <DUID_hex_string>")
    print("Example: decode_duid.py 00:01:00:01:2c:3d:4e:5f:aa:bb:cc:dd:ee:ff")
    print("DUID hex string is missing or extra arguments provided. Please try again.")
    sys.exit(1)

duid_hex_string = sys.argv[1]

# --- Input Validation and Conversion ---
try:
    # Remove colons and convert hex string to bytes
    duid_bytes = bytes.fromhex(duid_hex_string.replace(':', ''))
except ValueError:
    print(f"Error: Invalid hex string format provided: '{duid_hex_string}'")
    print("Ensure the string contains only hex characters (0-9, a-f, A-F) and optional colons.")
    sys.exit(1)

if len(duid_bytes) < 2:
    print(f"Error: DUID is too short ({len(duid_bytes)} bytes). Must be at least 2 bytes for the type field.")
    sys.exit(1)

# Use BytesIO to simulate reading from a file/stream
data = io.BytesIO(duid_bytes)
total_duid_length = len(duid_bytes) # Get total length from the input bytes

print(f'Input DUID Hex: {duid_hex_string}')
print(f'Total DUID Length: {total_duid_length} bytes')

# --- DUID Decoding ---
try:
    # Read DUID Type (first 2 bytes)
    duid_type_code = struct.unpack('!H', data.read(2))[0]
    duid_type_name = duid_types.get(duid_type_code, 'Unknown')
    print(f'DUID Type: {duid_type_code} [{duid_type_name}]')

    # Process based on DUID Type
    if duid_type_code == 1: # DUID-LLT
        if total_duid_length < 8: # Type(2) + HWType(2) + Time(4) = 8 bytes minimum
             raise ValueError("DUID-LLT is too short for fixed fields")
        hw_type_code = struct.unpack('!H', data.read(2))[0]
        hw_type_name = hw_types.get(hw_type_code, 'Unknown')
        print(f'Hardware Type: {hw_type_code} [{hw_type_name}]')

        time_val = struct.unpack('!I', data.read(4))[0]
        print(f'Seconds since midnight (UTC), January 1, 2000: {time_val}')

        # --- Calculate and print the actual datetime ---
        try:
            # DUID time epoch is midnight (UTC), January 1, 2000
            duid_epoch = datetime.datetime(2000, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
            # Calculate the actual timestamp by adding the seconds offset
            actual_datetime = duid_epoch + datetime.timedelta(seconds=time_val)
            # Print the calculated datetime in ISO format (includes timezone info)
            print(f'Calculated Timestamp (UTC): {actual_datetime.isoformat()}')
        except OverflowError:
            # Handle cases where time_val might be too large for datetime
            print(f'Warning: time_val ({time_val}) is too large to represent as a standard datetime.')
        except Exception as dt_err: # Catch potential datetime calculation errors
            print(f'Warning: Could not calculate datetime from time_val: {dt_err}')
        # --- End datetime calculation ---

        # Remaining bytes are the link-layer address
        address_len = total_duid_length - 8 # Type(2) + HWType(2) + Time(4)
        if address_len < 0: # Should be caught above, but double check
             raise ValueError("Calculated negative address length for DUID-LLT")
        lla_bytes = data.read(address_len)
        lla_hex = lla_bytes.hex()
        if hw_type_code == 1 and address_len == 6:   # Format Ethernet MAC address nicely
            print('Link-layer Address: {}'.format(
                ':'.join(lla_hex[i:i+2] for i in range(0, len(lla_hex), 2))))
        else:
            print(f'Link-layer Address: {":".join(lla_hex[i:i+2] for i in range(0, len(lla_hex), 2))} (Hex)')

    elif duid_type_code == 2: # DUID-EN
        if total_duid_length < 6: # Type(2) + EnterpriseNum(4) = 6 bytes minimum
             raise ValueError("DUID-EN is too short for fixed fields")
        enterprise_num = struct.unpack('!I', data.read(4))[0] # Read as unsigned 32-bit int
        print(f'Enterprise Number: {enterprise_num}')

        # Remaining bytes are the identifier
        identifier_len = total_duid_length - 6 # Type(2) + EnterpriseNum(4)
        if identifier_len < 0:
             raise ValueError("Calculated negative identifier length for DUID-EN")
        identifier_bytes = data.read(identifier_len)
        print(f'Identifier: 0x{identifier_bytes.hex()}') # Use f-string correctly

    elif duid_type_code == 3: # DUID-LL
        if total_duid_length < 4: # Type(2) + HWType(2) = 4 bytes minimum
             raise ValueError("DUID-LL is too short for fixed fields")
        hw_type_code = struct.unpack('!H', data.read(2))[0]
        hw_type_name = hw_types.get(hw_type_code, 'Unknown')
        print(f'Hardware Type: {hw_type_code} [{hw_type_name}]')

        # Remaining bytes are the link-layer address
        address_len = total_duid_length - 4 # Type(2) + HWType(2)
        if address_len < 0:
             raise ValueError("Calculated negative address length for DUID-LL")
        lla_bytes = data.read(address_len)
        lla_hex = lla_bytes.hex()
        if hw_type_code == 1 and address_len == 6:   # Format Ethernet MAC address nicely
            print('Link-layer Address: {}'.format(
                ':'.join(lla_hex[i:i+2] for i in range(0, len(lla_hex), 2))))
        else:
            print(f'Link-layer Address: {":".join(lla_hex[i:i+2] for i in range(0, len(lla_hex), 2))} (Hex)')

    elif duid_type_code == 4: # DUID-UUID
        expected_len = 18 # Type(2) + UUID(16)
        if total_duid_length != expected_len:
            raise ValueError(f"DUID-UUID must be exactly {expected_len} bytes long, found {total_duid_length}")

        uuid_bytes = data.read(16)
        # uuid_hex = uuid_bytes.hex() # Not needed directly if using from_bytes
        # uuid_obj = uuid.UUID(hex=uuid_hex)
        uuid_obj = uuid.UUID(bytes=uuid_bytes) # More direct way
        print(f'UUID: {str(uuid_obj)}')

    else:
        print('Unknown DUID Type. Unable to decode further.')
        # Optionally print the remaining raw bytes
        remaining_bytes = data.read()
        if remaining_bytes:
             print(f'Remaining undecoded data: 0x{remaining_bytes.hex()}')

except struct.error as e:
    print("\nError: Could not unpack data. The DUID might be truncated or malformed for the declared type.")
    print(f"Details: {e}")
    sys.exit(1)
except ValueError as e:
    print("\nError: Invalid DUID data for the declared type.")
    print(f"Details: {e}")
    sys.exit(1)
except Exception as e: # Catch any other unexpected errors during processing
    print(f"\nAn unexpected error occurred during decoding: {e}")
    sys.exit(1)

# Check if all bytes were consumed (optional sanity check)
remaining_bytes = data.read()
if remaining_bytes:
    print(f"\nWarning: {len(remaining_bytes)} bytes remaining in the input after decoding.")
    print(f"Remaining data: 0x{remaining_bytes.hex()}")

