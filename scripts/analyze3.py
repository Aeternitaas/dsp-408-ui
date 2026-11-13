#!/usr/bin/env python3
"""Deep structural analysis of DSP408 config stream."""

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

# Build stream using LENGTH field for correct data size
stream = bytearray()
for i in range(0x1D):
    h = raw_hex[i].replace(" ", "")
    raw = bytes.fromhex(h)
    pkt_len = raw[4]
    data_len = pkt_len - 2
    data = raw[7:7+data_len]
    # Pad with zeros if short
    if len(data) < data_len:
        data = data + bytes(data_len - len(data))
    stream.extend(data)

print(f"Total stream: {len(stream)} bytes\n")

# Find channels
ch_names = ['InA', 'InB', 'InC', 'InD', 'Out1', 'Out2', 'Out3', 'Out4', 'Out5', 'Out6', 'Out7', 'Out8']
ch_pos = {}
for name in ch_names:
    ch_pos[name] = stream.find(name.encode())

# ========================================================================
# The key insight from previous analysis:
# - Before each channel name, there's a pattern: ... 18 01 00 00 00 00 [ID_LO] [ID_HI] [NAME...]
# - The 2 bytes before the name are a channel ID (LE16):
#   InA=0x0000 (but preceded by global header), InB=0x0001, InC=0x0002, InD=0x0004
#   Out1=0x0008, Out2=0x0001, Out3=0x0002, Out4=0x0004, Out5=0x0008
#   Out6=0x0010, Out7=0x0020, Out8=0x0040
# - These are bitmask values!

# Let me find the actual record start for each channel
# Looking at the pattern: the consistent "footer/separator" before each name is:
# 18 01 00 00 00 00 [ID_lo] [ID_hi]
# So the record structure has a footer that includes 18 01 and then 6 more bytes

# Let's figure out the exact record boundaries
# ========================================================================

print("="*80)
print("=== RECORD BOUNDARY ANALYSIS ===")
print("="*80)

# For InB through Out8, show what's at name-8 to name
sorted_chs = sorted(ch_pos.items(), key=lambda x: x[1])
for name, off in sorted_chs:
    if off >= 8:
        before8 = stream[off-8:off]
        print(f"  {name:>5s} name-8: {before8.hex(' ')}")

# Now let me define the record start as name-2 (the channel ID is at name-2)
# Wait, looking more carefully:
# InB at 0x9c: bytes at 0x94-0x9c = 18 01 00 00 00 00 01 00
# That's: [18 01] [00 00] [00 00] [01 00] then InB name
# InC at 0x128: bytes at 0x120-0x128 = 18 01 00 00 00 00 02 00
# Same pattern!
# So: ... data ... 18 01 00 00 00 00 [ch_id LE16] [8-byte name] ...

# The "18 01" = 0x0118 = 280 as LE16 - but what does it mean?
# Let's check if this is a "level" or "volume" value (280 encoding)

# Record layout hypothesis:
# [2B ch_id] [8B name] [2B ??] [data...] [2B level=0x0118] [2B ??] [2B ??]
# No wait, the 18 01 is at the END of the previous channel, as a footer

# Let me trace InA fully
print("\n" + "="*80)
print("=== InA FULL RECORD (name at 0x{:04x}) ===".format(ch_pos['InA']))
print("="*80)

ina = ch_pos['InA']
# Record: name starts at ina, preceded by some header
# name-2 bytes should be the channel ID
# For InA it's preceded by global header, so let's look at the pattern differently

# From hex dump:
# 0090: 2c 01 00 00 18 01 00 00 00 00 01 00 49 6e 42
# So for InB: the separator is [2c 01 00 00] [18 01 00 00] [00 00 01 00] [InB name...]
# That's 12 bytes before the name
# But [00 00 01 00] = 2 bytes padding + 2 bytes ch_id
# Or is it [00 00] [00 00] [01 00]?

# Let me look at the LAST bytes of InA's data region:
# InA name at 0x10
# InA data from 0x10 to wherever InB record starts
# InB name at 0x9c
# Before InB: ...2c 01 00 00 18 01 00 00 00 00 01 00 InB
# The 01 00 at offset 0x9a is the InB channel ID (bitmask=0x0001)
# The 00 00 at 0x98 seems to be padding
# The 18 01 at 0x94 is either part of InA's trailer or a separator

# Let me check: do ALL channels have this pattern?
print("\n--- 12 bytes before each channel name ---")
for name, off in sorted_chs:
    if off >= 12:
        before = stream[off-12:off]
        print(f"  {name:>5s}: {before.hex(' ')}")

# Looking at the pattern more carefully for outputs:
# Out1 at 0x23e: before 12 = 0x232: 18 01 00 00 00 00 08 00
# Out2 at 0x2a6: before 12 = 0x29a: dc 00 18 01 00 00 00 00 01 00 -- wait that's only 10
# Let me check Out2: 0x29a to 0x2a6 = 12 bytes

# Actually let me look at constant patterns
print("\n--- Searching for the '00 00 [id] 00' pattern before names ---")
for name, off in sorted_chs:
    # name-2: channel ID (LE16)
    # name-4: should be 00 00
    if off >= 4:
        id_val = stream[off-2] | (stream[off-1] << 8)
        pad = stream[off-4:off-2]
        print(f"  {name:>5s}: pad={pad.hex(' ')}, ch_id=0x{id_val:04x} ({id_val})")

# ========================================================================
# NOW: Full layout analysis
# ========================================================================
print("\n" + "="*80)
print("=== InA FULL BYTE-BY-BYTE ANALYSIS ===")
print("="*80)

# InA starts at name offset 0x10
# Before that: 2 bytes global flags (0xffff) + 14 bytes scene name ("Forest" padded to 14)
# Actually 0x00-0x01 = ff ff, 0x02-0x0f = "Forest          " (14 bytes)
# Then InA name at 0x10

# InA channel ID: what's at 0x0e-0x0f?
print(f"Global header: {stream[0:2].hex(' ')} = flags/version?")
print(f"Scene name: {stream[2:16].hex(' ')} = '{stream[2:16].decode('latin-1').rstrip()}'")

# The scene name is 14 bytes. But let's check if the ch_id is BEFORE the name
# InA's ch_id would be at 0x0e-0x0f but that's part of the scene name padding
# Let's see: 0x0e=0x20 (space), 0x0f=0x20 (space) - that's scene name padding!

# So maybe the record structure is different for InA (first channel)
# Let's focus on what we know works: InB, InC, InD all have:
# [00 00] [ch_id LE16] [name 8B] [header 8B] [GEQ 62B] ...

# For InA, the [00 00] [ch_id] might not exist or be different since it's the first

# Let's measure InA's data region using InB's known boundary
# InB starts at: InB_name - 4 = 0x9c - 4 = 0x98 (where 00 00 ch_id starts)
# Actually: 00 00 01 00 = at 0x98-0x9b, InB name at 0x9c
# So InB record starts at 0x98

# InA name at 0x10
# Before that are scene header bytes
# InA data ends at 0x98 (where InB record header begins)
# But wait, what about the "18 01 00 00" at 0x94-0x97?

# Let me check the structure hypothesis:
# Each channel record: [4B: 00 00 ch_id_LE16] [8B name] [header...] [GEQ/PEQ data] [trailer: ... 18 01 00 00]
# NO wait, the 18 01 could be part of the trailer of the PREVIOUS channel

# Let me try: the separator between channels is fixed at some number of bytes
# From InA to InB: InA name at 0x10, InB name at 0x9c
# Diff = 0x8c = 140 bytes between names
# If we subtract the 4-byte record header (00 00 ch_id) before InB: 140 - 4 = 136 bytes per InA's payload+trailer

# InA payload analysis:
# name+0..7 : name (8B)
# name+8..9 : 00 00 (2B)
# name+10..11 : 63 00 = 99 (2B LE16) -- level?
# name+12..13 : 63 00 = 99 (2B LE16) -- level?
# name+14..15 : 00 00 (2B)
# name+16..77 : GEQ 31 bands x 2B = 62B
# name+78..?? : PEQ + filters + trailer

# After GEQ for InA (name+78 onwards):
print(f"\n--- InA after GEQ (name+78) ---")
ina_after_geq = ina + 78
# Show as raw bytes with word grouping
for j in range(ina_after_geq, ina + 140):
    off_from_name = j - ina
    print(f"  name+{off_from_name:3d} [0x{j:04x}]: 0x{stream[j]:02x} ({stream[j]:3d})")

# Let me try to identify PEQ structure differently
# The user says PEQ is 6 bytes: [gain_lo gain_hi freq_lo freq_hi Q type]
# Looking at InA post-GEQ:
# +78: 96 00 = gain LE16 = 150 (+3.0 dB)
# +80: bc 00 = freq LE16 = 188
# +82: 00 = Q
# +83: 00 = type
# -> PEQ band 0: gain=150, freq=188, Q=0, type=0

# +84: 78 00 = gain=120 (0dB)
# +86: 47 00 = freq=71
# +88: 23 = Q=35
# +89: 00 = type=0
# -> PEQ band 1: gain=120, freq=71, Q=35, type=0

# +90: 78 00 = gain=120
# +92: 65 00 = freq=101
# +94: 23 = Q=35
# +95: 00 = type=0
# -> PEQ band 2

# This continues! Let me count:
print(f"\n--- InA PEQ bands (6 bytes each, starting name+78) ---")
pos = ina + 78
band = 0
while True:
    gain = stream[pos] | (stream[pos+1] << 8)
    freq = stream[pos+2] | (stream[pos+3] << 8)
    q = stream[pos+4]
    typ = stream[pos+5]
    gain_db = (gain - 120) / 10.0
    print(f"  PEQ[{band:2d}] name+{pos-ina:3d} [0x{pos:04x}]: gain={gain:3d}({gain_db:+5.1f}dB) freq={freq:4d} Q={q:3d} type={typ}")

    pos += 6
    band += 1

    # Check if next 6 bytes look like PEQ or if we've hit something else
    if pos + 6 > ina + 140:
        break
    next_gain = stream[pos] | (stream[pos+1] << 8)
    # If gain is 0x0000 and freq is very high, probably not PEQ
    if band >= 8 and next_gain == 0 and stream[pos+2] == 0:
        # Looks like padding
        break
    if band >= 12:  # safety limit
        break

print(f"\n  Total PEQ bands: {band}")
print(f"  After PEQ: name+{pos-ina} [0x{pos:04x}]")

# Show remaining bytes after PEQ
print(f"\n--- InA remaining after PEQ ---")
for j in range(pos, ina + 140):
    print(f"  name+{j-ina:3d} [0x{j:04x}]: 0x{stream[j]:02x} ({stream[j]:3d})")

# Now let's look at the END of InA more carefully
# The pattern before InB is: ... 2c 01 00 00 18 01 00 00 00 00 01 00 InB
# Let's look at InA's last 16 bytes (before InB name-4):
inb = ch_pos['InB']
ina_data_end = inb - 4  # before the 00 00 ch_id of InB
print(f"\n--- InA tail (last 16 bytes before InB record) ---")
for j in range(max(ina, ina_data_end - 16), ina_data_end):
    print(f"  name+{j-ina:3d} [0x{j:04x}]: 0x{stream[j]:02x} ({stream[j]:3d})")

# ========================================================================
# Out1 analysis
# ========================================================================
print("\n" + "="*80)
print("=== Out1 FULL BYTE-BY-BYTE ANALYSIS ===")
print("="*80)

out1 = ch_pos['Out1']
out2 = ch_pos['Out2']
out1_data_end = out2 - 4  # before Out2's record header

print(f"Out1 name at 0x{out1:04x}")
print(f"Out1 data region: name+0 to name+{out1_data_end - out1} ({out1_data_end - out1} bytes)")

# Name (8B)
print(f"\nname+ 0..7  NAME    : {stream[out1:out1+8].hex(' ')} = '{stream[out1:out1+4].decode()}'")

# Post-name bytes
print(f"name+ 8..9  ??      : {stream[out1+8:out1+10].hex(' ')} = LE16 {stream[out1+8] | (stream[out1+9]<<8)}")
# Output channels don't have GEQ, so what follows the name header?

# Let's look at all output channels' bytes at name+8, +9 (the byte after the name+null padding)
print(f"\n--- Output channel name+8..9 values ---")
for name in ['Out1', 'Out2', 'Out3', 'Out4', 'Out5', 'Out6', 'Out7', 'Out8']:
    o = ch_pos[name]
    val = stream[o+8] | (stream[o+9] << 8)
    print(f"  {name}: 0x{val:04x} ({val}) = {(val-120)/10.0:+.1f} dB?  or flags?")

# name+10..17 for outputs: 18 01 18 01 18 01 18 01 = four copies of 0x0118
print(f"\n--- Output channel name+10..17 (4x LE16) ---")
for name in ['Out1', 'Out2', 'Out3', 'Out4', 'Out5', 'Out6', 'Out7', 'Out8']:
    o = ch_pos[name]
    vals = []
    for k in range(4):
        v = stream[o+10+k*2] | (stream[o+11+k*2] << 8)
        vals.append(f"0x{v:04x}")
    print(f"  {name}: {', '.join(vals)}")

# name+18..19 for outputs
print(f"\n--- Output channel name+18..23 ---")
for name in ['Out1', 'Out2', 'Out3', 'Out4', 'Out5', 'Out6', 'Out7', 'Out8']:
    o = ch_pos[name]
    hx = stream[o+18:o+24].hex(' ')
    vals_le16 = []
    for k in range(3):
        v = stream[o+18+k*2] | (stream[o+19+k*2] << 8)
        vals_le16.append(f"0x{v:04x}")
    print(f"  {name}: {hx}  LE16={', '.join(vals_le16)}")

# Now let's try PEQ parsing for Out1 starting at name+24
print(f"\n--- Out1 PEQ parse from name+24 ---")
pos = out1 + 24
band = 0
while pos + 6 <= out1_data_end:
    gain = stream[pos] | (stream[pos+1] << 8)
    freq = stream[pos+2] | (stream[pos+3] << 8)
    q = stream[pos+4]
    typ = stream[pos+5]
    gain_db = (gain - 120) / 10.0
    print(f"  PEQ[{band:2d}] name+{pos-out1:3d} [0x{pos:04x}]: gain={gain:3d}({gain_db:+5.1f}dB) freq={freq:4d} Q={q:3d} type={typ}")
    pos += 6
    band += 1
    if band >= 12:
        break

print(f"\n  After 12 PEQ bands: name+{pos-out1}")

# Remaining after PEQ
print(f"\n--- Out1 remaining after PEQ ---")
for j in range(pos, out1_data_end):
    print(f"  name+{j-out1:3d} [0x{j:04x}]: 0x{stream[j]:02x} ({stream[j]:3d})")

# Let's look at the tail pattern (HPF/LPF)
# From Out1: after PEQ band 11, we should have some filter data, then the separator
# The separator should be: ... dc 00 18 01 00 00

# ========================================================================
# Let me try to parse filters from the remaining bytes
# ========================================================================
print(f"\n--- Analyzing filter/tail data for Out1 ---")
tail = stream[pos:out1_data_end]
print(f"Tail bytes ({len(tail)} bytes): {tail.hex(' ')}")

# The tail for InA was: 00 00 2c 01 00 00 18 01 00 00
# 2c 01 = 300, 18 01 = 280
# For Out1: let's see what's after PEQ

# Let's check ALL channel tails (last N bytes before next channel's record header)
print(f"\n--- Channel tails (last 14 bytes) ---")
all_chs = sorted(ch_pos.items(), key=lambda x: x[1])
for i, (name, off) in enumerate(all_chs):
    if i + 1 < len(all_chs):
        end = all_chs[i+1][1] - 4  # before next channel's 4-byte header
    else:
        end = len(stream)

    if end - off > 14:
        tail_start = end - 14
        tail = stream[tail_start:end]
        print(f"  {name:>5s}: tail = {tail.hex(' ')}")

# ========================================================================
# The full Out3 analysis to see PEQ with non-default values
# ========================================================================
print("\n" + "="*80)
print("=== Out3 DETAILED (has non-default PEQ values) ===")
print("="*80)
out3 = ch_pos['Out3']
out4 = ch_pos['Out4']
out3_end = out4 - 4

print(f"Out3 name at 0x{out3:04x}, data region {out3_end - out3} bytes")
print(f"\n--- Full dump ---")
for j in range(out3, out3_end):
    ch = chr(stream[j]) if 32 <= stream[j] < 127 else '.'
    print(f"  name+{j-out3:3d} [0x{j:04x}]: 0x{stream[j]:02x} ({stream[j]:3d}) '{ch}'")

print(f"\n--- Out3 PEQ parse from name+18 ---")
pos = out3 + 18
band = 0
while pos + 6 <= out3_end and band < 15:
    gain = stream[pos] | (stream[pos+1] << 8)
    freq = stream[pos+2] | (stream[pos+3] << 8)
    q = stream[pos+4]
    typ = stream[pos+5]
    gain_db = (gain - 120) / 10.0
    print(f"  PEQ[{band:2d}] name+{pos-out3:3d}: gain={gain:3d}({gain_db:+5.1f}dB) freq={freq:4d} Q={q:3d} type={typ}")
    pos += 6
    band += 1

# ========================================================================
# Now parse Out3 from name+20 with different interpretation
# ========================================================================
print(f"\n--- Out3 PEQ parse from name+20 ---")
pos = out3 + 20
band = 0
while pos + 6 <= out3_end and band < 15:
    gain = stream[pos] | (stream[pos+1] << 8)
    freq = stream[pos+2] | (stream[pos+3] << 8)
    q = stream[pos+4]
    typ = stream[pos+5]
    gain_db = (gain - 120) / 10.0
    print(f"  PEQ[{band:2d}] name+{pos-out3:3d}: gain={gain:3d}({gain_db:+5.1f}dB) freq={freq:4d} Q={q:3d} type={typ}")
    pos += 6
    band += 1
