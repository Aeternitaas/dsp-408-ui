#!/usr/bin/env python3
"""Second-pass analysis: check chunk data sizes and alignment."""

# The header byte at offset 4 is the length of the remaining payload (after the 5-byte frame header).
# Frame: [10] [02] [01] [00] [LEN] [payload of LEN bytes] [10] [03] [CHECKSUM]
# So payload = LEN bytes starting at offset 5
# Within payload: byte[0]=cmd(0x24), byte[1]=sub-index, bytes[2..LEN-1]=data
# Data length = LEN - 2

# But the user says footer (10 03 checksum) is NOT in the hex strings.
# Let's check: are the hex strings exactly 5 + LEN bytes (no footer)?
# Or are they 5 + LEN + 3 bytes (with footer)?

raw_hex = {
    0x00: "10020100342400ffff466f726573742020202020202020496e4100000000000000630063000000780078007800780078007800780078007800",
    0x01: "1002010034240178007800780078007800780078007800780078007800490078007800780078007800780078007800780078009600bc000000",
    0x02: "1002010034240278004700230078006500230078008c0023007800aa0023007800c80023007800f000230078000e01230000002c010000180100",
    0x03: "10020100342403000000000100496e420000000000000063006300000078007800780078007800780078007800780078007800780078007800",
    0x04: "10020100342404780078007800780078007800490078007800780078007800780078007800780078007800290023007800470023007800650000",
    0x05: "10020100342405230078008c0023007800aa0023007800c80023007800f000230078000e01230000002c0100001801000000000200496e430000",
    0x06: "10020100342406000000000000630063000000780078007800780078007800780078007800780078007800780078007800780078003c003c0000",
    0x07: "100201003424073c005a0078007800780078003c007800780078007800780078002900230078004700230078006500230078008c00230078",
    0x08: "10020100342408aa0023007800c80023007800f000230078000e01230000002c0100001801000000000400496e44000000000000006300630000",
    0x09: "100201003424090000780078007800780078007800780078007800780078007800780078007800780078003c003c003c005a0078007800780000",
    0x0a: "1002010034240a78003c007800780078007800780078002900230078004700230078006500230078008c0023007800aa0023007800c80023",
    0x0b: "1002010034240b7800f000230078000e01230000002c01000018010000000008004f757431000000000f0018011801180118010b003d000808",
    0x0c: "1002010034240c78001f00230078003f00230078005f00230078007f00230078009e0023007800be0023007800de0023007800fd002300780000",
    0x0d: "1002010034240d1d01230000003100f3010000dc003100f3010000dc001801000000000100 4f75743200000000050018011801180118013d0000",
    0x0e: "1002010034240e5b000803c800a5001c00a000bc00000078005f00230078007f00230078009e0023007800be0023007800de0023007800fd00",
    0x0f: "1002010034240f230078001d01230000003100f3010000dc003100f3010000dc0018010000000002004f75743300000000050018011801180100",
    0x10: "1002010034241018017f00ee000a033200ba001e003c00d1002d004000ed0028008400f5003300a000f4000a029600bc0000006700ca002300",
    0x11: "100201003424117800fd00230078001d01230000003100f3010000dc003100f3010000dc001801000000000400 4f757434000000000a001801",
    0x12: "100201003424121801180118013d005b000803c800a5001c00a000bc00000078005f00230078007f00230078009e0023007800be00230078",
    0x13: "10020100342413de0023007800fd00230078001d01230000003100f3010000dc003100f3010000dc0018010000000008004f75743500000000",
    0x14: "100201003424140a0018011801180118017f00ee000a033200ba001e003c00d1002d004100ed0028008400f5003300a000f4000a029600bc00",
    0x15: "1002010034241500007800de0023007800fd00230078001d01230000003100f3010000dc003100f3010000dc001801000000001000 4f75743600",
    0x16: "1002010034241600000000050018011801180118013d000a01080378001f00230078003f00230078005f00230078007f00230078009e002300",
    0x17: "100201003424177800be0023007800de0023007800fd00230078001d01230000003100f3010000dc003100f3010000dc001801000000002000",
    0x18: "100201003424184f757437000000000a0018011801180118013d000a01080378001f00230078003f00230078005f00230078007f0023007800",
    0x19: "100201003424199e0023007800be0023007800de0023007800fd00230078001d01230000003100f3010000dc003100f3010000dc0018010000",
    0x1a: "1002010034241a000040004f757438000000000f00180118011801180100002c01000078001f00230078003f00230078005f00230078007f00",
    0x1b: "1002010034241b230078009e0023007800be0023007800de0023007800fd00230078001d01230000003100f3010000dc003100f3010000dc00",
    0x1c: "1002010032241c18010000000080000000000001000000000000000000fc01c001fc01c0010000000000000000000000000000000000",
}

print("=== CHUNK SIZE ANALYSIS ===")
for i in range(0x1D):
    h = raw_hex[i].replace(" ", "")
    raw = bytes.fromhex(h)
    pkt_len = raw[4]  # The length byte
    total_raw = len(raw)
    expected_no_footer = 5 + pkt_len  # 5-byte header + payload
    expected_with_footer = 5 + pkt_len + 3  # with 10 03 XX footer
    data_len = pkt_len - 2  # subtract cmd + sub-index

    status = ""
    if total_raw == expected_no_footer:
        status = "EXACT (no footer)"
    elif total_raw == expected_with_footer:
        status = "EXACT (with footer)"
    elif total_raw < expected_no_footer:
        status = f"SHORT by {expected_no_footer - total_raw}"
    else:
        status = f"LONG by {total_raw - expected_no_footer}"

    print(f"  Chunk 0x{i:02x}: LEN=0x{pkt_len:02x}({pkt_len}), raw_bytes={total_raw}, "
          f"expected_no_footer={expected_no_footer}, data_should_be={data_len} bytes, {status}")

# The correct data per chunk should be pkt_len - 2 bytes (from offset 7)
# Let's rebuild the stream using the LENGTH field to determine exact data size
print("\n=== REBUILDING STREAM USING LENGTH FIELD ===")
stream = bytearray()
for i in range(0x1D):
    h = raw_hex[i].replace(" ", "")
    raw = bytes.fromhex(h)
    pkt_len = raw[4]
    data_len = pkt_len - 2  # cmd + sub-index
    data = raw[7:7+data_len]

    if len(data) < data_len:
        print(f"  WARNING: Chunk 0x{i:02x}: only {len(data)} bytes available, expected {data_len}")

    print(f"  Chunk 0x{i:02x}: stream_offset=0x{len(stream):04x}, data_len={len(data)}")
    stream.extend(data)

print(f"\nTotal stream (length-corrected): {len(stream)} bytes")

# Now find channels again
ch_names = ['InA', 'InB', 'InC', 'InD', 'Out1', 'Out2', 'Out3', 'Out4', 'Out5', 'Out6', 'Out7', 'Out8']
ch_pos = {}
for name in ch_names:
    idx = stream.find(name.encode())
    ch_pos[name] = idx

sorted_chs = sorted(ch_pos.items(), key=lambda x: x[1])
print("\n=== CHANNEL OFFSETS (length-corrected) ===")
for i, (n, o) in enumerate(sorted_chs):
    nxt = sorted_chs[i+1][1] if i+1 < len(sorted_chs) else len(stream)
    print(f"  {n:>5s}: 0x{o:04x} ({o:4d}), size to next = {nxt - o}")

# Check alignment: all input channels should have same structure
print("\n=== INPUT CHANNEL FIRST 20 BYTES ===")
for name in ['InA', 'InB', 'InC', 'InD']:
    o = ch_pos[name]
    hx = stream[o:o+20].hex(' ')
    print(f"  {name}: {hx}")

print("\n=== OUTPUT CHANNEL FIRST 40 BYTES ===")
for name in ['Out1', 'Out2', 'Out3', 'Out4', 'Out5', 'Out6', 'Out7', 'Out8']:
    o = ch_pos[name]
    hx = stream[o:o+40].hex(' ')
    print(f"  {name}: {hx}")

# Full hex dump
print("\n=== FULL HEX DUMP (length-corrected) ===")
for off in range(0, len(stream), 16):
    hx = " ".join(f"{b:02x}" for b in stream[off:off+16])
    asc = "".join(chr(b) if 32 <= b < 127 else "." for b in stream[off:off+16])
    print(f"  {off:04x}: {hx:<48s}  {asc}")
