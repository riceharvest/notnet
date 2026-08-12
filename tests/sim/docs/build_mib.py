#!/usr/bin/env python3
"""Build a minimal Realtek MIB flash image for the TOTOLINK Boa (#126).

Writes [COMPRESS_MIB_HEADER_T: sig=Hf compRate=1 compLen=<n>][LZSS data]
at flash offset 0x6000 of the mtdblock0 the boa reads. The decompressed
MIB is a mostly-zero struct with the fields the asp layer needs.
"""
import struct, sys

N, F, THRESHOLD = 4096, 18, 2

def lzss_encode(data: bytes) -> bytes:
    out = bytearray()
    text_buf = bytearray(b' ' * (N + F - 1))
    r = N - F
    mask = 0x01
    i = 0
    s = len(data)
    code_buf = bytearray(17)
    code_buf[0] = 0

    while i < s:
        match_pos = match_len = 0
        if i < s - 1:
            for p in range(max(0, r - (N - 1)), r + 1):
                ln = 0
                while ln < F - 1 and i + ln < s and text_buf[(p + ln) & (N - 1)] == data[i + ln]:
                    ln += 1
                if ln > match_len:
                    match_len = ln
                    match_pos = p
        if match_len > THRESHOLD and i + match_len <= s:
            code_buf[0] |= mask
            code_buf.append(match_pos & 0xFF)
            code_buf.append((((match_pos >> 4) & 0xF0) | (match_len - THRESHOLD - 1)) & 0xFF)
            for k in range(match_len + 1):
                if i >= s:
                    break
                text_buf[r] = data[i]
                i += 1
                r = (r + 1) & (N - 1)
        else:
            c = data[i]
            code_buf.append(c)
            text_buf[r] = c
            i += 1
            r = (r + 1) & (N - 1)
        mask <<= 1
        if mask == 0x100:
            out += bytes(code_buf)
            code_buf = bytearray(17)
            code_buf[0] = 0
            mask = 0x01
    if len(code_buf) > 1:
        out += bytes(code_buf)
    return bytes(out)

def build():
    mib = bytearray(2048)
    mib[0x00:0x0B] = b'N300RT'          # model name (MIB_MODEL_NAME)
    mib[0x0B:0x11] = b'V2.2.0'          # sys version
    mib[0x20:0x2C] = b'192.168.1.1'     # lan ip
    mib[0xDB:0xE1] = b'admin'           # web username
    mib[0x100:0x106] = b'123456'        # web password
    payload = lzss_encode(bytes(mib))
    header = b'Hf' + struct.pack('>HI', 1, len(payload))
    blob = header + payload
    print(f"LZSS: {len(bytes(mib))} -> {len(payload)} bytes, blob {len(blob)}")
    return blob

if __name__ == '__main__':
    blob = build()
    if len(sys.argv) > 1:
        mtd = sys.argv[1]
        with open(mtd, 'r+b') as f:
            f.seek(0x6000)
            f.write(blob)
        print(f"wrote {len(blob)} bytes at 0x6000 of {mtd}")
    else:
        with open('/tmp/mib.bin', 'wb') as f:
            f.write(blob)
        print("wrote /tmp/mib.bin")
