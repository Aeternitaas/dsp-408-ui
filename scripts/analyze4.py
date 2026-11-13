#!/usr/bin/env python3
"""Final structural analysis - determine PEQ count and filter layout."""

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

stream = bytearray()
for i in range(0x1D):
    h = raw_hex[i].replace(" ", "")
    raw = bytes.fromhex(h)
    pkt_len = raw[4]
    data_len = pkt_len - 2
    data = raw[7:7+data_len]
    if len(data) < data_len:
        data = data + bytes(data_len - len(data))
    stream.extend(data)

ch_names = ['InA', 'InB', 'InC', 'InD', 'Out1', 'Out2', 'Out3', 'Out4', 'Out5', 'Out6', 'Out7', 'Out8']
ch_pos = {}
for name in ch_names:
    ch_pos[name] = stream.find(name.encode())

sorted_chs = sorted(ch_pos.items(), key=lambda x: x[1])

# ========================================================================
# KEY INSIGHT: Looking at InA tail again
# The tail for inputs is: ... [last PEQ] 00 00 2c 01 00 00 18 01 00 00
# For outputs:            ... [last PEQ] 00 00 31 00 f3 01 00 00 dc 00 31 00 f3 01 00 00 dc 00 18 01 00 00
#
# Let me look at it from the PEQ perspective.
# InA PEQ data starts at name+78.
# Looking at bytes: 96 00 bc 00 00 00 | 78 00 47 00 23 00 | 78 00 65 00 23 00 | ...
# The repeating pattern 78 00 [freq] 00 23 00 makes these look like 6-byte PEQ bands.
# Q=0x23=35 is a common Q value for PEQ.
# type=0 is parametric EQ (PEQ).
#
# For InA, the PEQ frequencies are: 71, 101, 140, 170, 200, 240, 270
# These look like specific frequencies. The first band has gain=150, freq=188, Q=0.
#
# After the last PEQ band (gain=120, freq=270, Q=35, type=0), we have:
# 00 00 2c 01 00 00 18 01 00 00
# That's 10 bytes = possibly:
# [00 00] = padding/null PEQ marker
# [2c 01] [00 00] = HPF freq LE16=300, HPF type/slope
# [18 01] [00 00] = LPF freq LE16=280, LPF type/slope
# Wait, 2c 01 = 300, 18 01 = 280? That doesn't make sense for HPF/LPF (HPF should be < LPF)
# Unless: HPF freq=300 means freq encoding = 300 (like 30.0 Hz?)
# Or: these aren't HPF/LPF but something else
#
# For outputs, the tail is: 00 00 31 00 f3 01 00 00 dc 00 31 00 f3 01 00 00 dc 00 18 01 00 00
# 31 00 = 49, f3 01 = 499, 00 00 = 0, dc 00 = 220
# Doubled: same 4 values twice: [31 00 f3 01 00 00 dc 00] x 2
# Then 18 01 00 00
# ========================================================================

# Let me reconsider: the PEQ BAND COUNT might be visible in the header
# Input header: name+8: 00 00, name+10: 63 00, name+12: 63 00, name+14: 00 00
# The 63 = 99 decimal. Could be level (99 out of 100)?
# Output header: name+8: 0f 00 (or 05 00 etc) - flags/config byte

# Let me count PEQ bands differently.
# For Out1: the structure at name+18 starts with [0b 00 3d 00 08 08]
# For Out2: [3d 00 5b 00 08 03]
# For Out8: [00 00 2c 01 00 00]
# These 6 bytes before PEQ might be HPF/LPF data!

# HYPOTHESIS: Output channel structure:
# [8B name] [2B flags] [8B: 4x LE16 source routing] [6B: HPF/LPF] [N*6B PEQ] [tail]
#
# Let me check: if HPF/LPF is at name+18 (6 bytes), then PEQ starts at name+24
# Out1 PEQ from +24: gain=120, freq=31, Q=35, type=0 -- looks great!
# Out3 PEQ from +24: gain=50, freq=186, Q=30, type=0 -- could work for non-default
# Out8 PEQ from +24: gain=120, freq=31, Q=35, type=0 -- looks great!
#
# But wait, for Out8, the bytes at +18 are: 00 00 2c 01 00 00
# 00 00 = LE16 0 (HPF off?)
# 2c 01 = LE16 300 (LPF freq?)
# 00 00 = LE16 0 (slope/type?)
# Hmm, that's only 3x LE16 = 6 bytes for HPF+LPF? Maybe:
# [2B HPF_freq] [2B LPF_freq] [1B HPF_slope] [1B LPF_slope]?

# For Out1: 0b 00 3d 00 08 08
# HPF=11, LPF=61, HPF_slope=8, LPF_slope=8
# For Out2: 3d 00 5b 00 08 03
# HPF=61, LPF=91, HPF_slope=8, LPF_slope=3
# For Out8: 00 00 2c 01 00 00
# HPF=0, LPF=300, HPF_slope=0, LPF_slope=0

# Now, after the PEQ bands, what's left?
# Out1 from +24, with 9 PEQ bands (through freq=285):
# PEQ[0-8] = 9 bands * 6 = 54 bytes -> ends at +78
# Then: 00 00 31 00 f3 01 00 00 dc 00 31 00 f3 01 00 00 dc 00 18 01 00 00
# That's 20 bytes

# But if we parse 9 PEQ from Out1 starting at +24:
# +24: gain=120 freq=31 Q=35 type=0  <-- this is default at 31 Hz
# ...
# +72: gain=120 freq=285 Q=35 type=0 <-- last one at 285
# That's 9 bands (24,30,36,42,48,54,60,66,72) = 9 * 6 = 54 -> next at +78

# At +78: 00 00 31 00 f3 01 00 00 dc 00 | 31 00 f3 01 00 00 dc 00 | 18 01 00 00
# That's: [2B] [2B] [2B] [2B] [2B] | [2B] [2B] [2B] [2B] [2B] | [2B] [2B]
# = 00 00 | 31 00 | f3 01 | 00 00 | dc 00 || 31 00 | f3 01 | 00 00 | dc 00 || 18 01 | 00 00
# = 0, 49, 499, 0, 220, 49, 499, 0, 220, 280, 0

# Hmm. The "00 00" at +78 could be a terminator for PEQ.
# Then we have two identical 8-byte blocks: [31 00 f3 01 00 00 dc 00] x 2
# 0x0031=49, 0x01f3=499, 0x0000=0, 0x00dc=220
# Then [18 01 00 00] = [0x0118=280, 0x0000=0]

# For INPUTS, the tail after PEQ is:
# 00 00 2c 01 00 00 18 01 00 00
# 0, 300, 0, 280, 0
# Much shorter! No doubled block.

# So the structure difference is:
# INPUT tail (10 bytes): 00 00 | 2c 01 00 00 | 18 01 00 00
# OUTPUT tail (20 bytes): 00 00 | 31 00 f3 01 00 00 dc 00 | 31 00 f3 01 00 00 dc 00 | 18 01 00 00

# ========================================================================
# LET ME RE-EXAMINE: How many PEQ bands are there?
# ========================================================================

# For INPUTS: PEQ at name+78, tail at 10 bytes before record end
# Record size from name to next record header = 136 bytes (140 - 4 for record header)
# Name(8) + Header(8) + GEQ(62) + PEQ(?) + Tail(10) = 136
# PEQ = 136 - 8 - 8 - 62 - 10 = 48 bytes = 8 bands * 6 bytes
# YES! 8 PEQ bands for inputs!

# For OUTPUTS: PEQ at name+24, tail at 20 bytes before record end
# Record size from name to next record header = 100 bytes (104 - 4)
# Name(8) + Header(2) + Routing(8) + HPF/LPF(6) + PEQ(?) + Tail(20) = 100
# PEQ = 100 - 8 - 2 - 8 - 6 - 20 = 56 bytes... but that's not divisible by 6!

# Hmm. Let me reconsider. Maybe tail is different.

# Let me think about Out1 more carefully.
# name+0..7: "Out1\x00\x00\x00\x00" (8 bytes)
# name+8..9: 0f 00 (2 bytes)
# name+10..17: 18 01 18 01 18 01 18 01 (8 bytes)
# name+18..23: 0b 00 3d 00 08 08 (6 bytes)
# name+24..77: PEQ bands (54 bytes = 9 bands)
# name+78..79: 00 00 (2 bytes - terminator/padding)
# name+80..87: 31 00 f3 01 00 00 dc 00 (8 bytes - filter block 1)
# name+88..95: 31 00 f3 01 00 00 dc 00 (8 bytes - filter block 2)
# name+96..99: 18 01 00 00 (4 bytes - level/trim)
# Total: 8+2+8+6+54+2+8+8+4 = 100. That's 100 bytes!

# For Out2 record end: Out2 at 0x2a6, Out3 at 0x310
# Record header (00 00 02 00) before Out3 at 0x30c-0x30f
# So Out2 data: 0x2a6 to 0x30c = 102 bytes
# Wait, but I calculated 100 earlier. Let me recheck.

# Out1 at 0x240, Out2 at 0x2a6
# Before Out2: record header at 0x2a2 (00 00 01 00)
# So Out1 data: 0x240 to 0x2a2 = 98 bytes... that doesn't match either.

# Let me be more precise.
print("=== PRECISE RECORD BOUNDARIES ===")
for i, (name, off) in enumerate(sorted_chs):
    # Find where the "00 00 [ch_id] [name]" pattern starts for this channel
    # Pattern: 00 00 XX 00 NAME (the XX 00 is the ch_id LE16)
    # For InA, it's preceded by scene name, so no standard header
    if i == 0:
        rec_start = off  # InA: record starts at name
        print(f"  {name:>5s}: rec_start=0x{rec_start:04x} (name)")
    else:
        # Check if 00 00 is at name-4
        rec_start = off - 4
        pre = stream[rec_start:rec_start+4]
        print(f"  {name:>5s}: rec_start=0x{rec_start:04x}, header=[{pre.hex(' ')}]")

# Let me compute record sizes differently
# Each record ENDS just before the next record's 4-byte header
# The last record ends at the end of stream (minus global trailer)
print("\n=== RECORD DATA SIZES (name to end of record) ===")
for i, (name, off) in enumerate(sorted_chs):
    if i + 1 < len(sorted_chs):
        nxt_off = sorted_chs[i+1][1]
        rec_data_end = nxt_off - 4  # subtract 4-byte record header of next channel
    else:
        # Last channel: find where the global trailer starts
        # After Out8, at name+96: 18 01 00 00, then at +100: 00 00 80 00 ...
        # The record probably ends at +100 and the rest is global trailer
        rec_data_end = off + 100  # estimate

    rec_data_size = rec_data_end - off
    print(f"  {name:>5s}: name at 0x{off:04x}, data ends at 0x{rec_data_end:04x}, size = {rec_data_size}")

# Let me look at the record header more carefully
# The 4 bytes before each name (except InA) are: [00 00] [ch_id LE16]
# But looking at inputs: "2c 01 00 00 18 01 00 00 00 00 01 00 InB"
# That's more than 4 bytes. Let me count what belongs to InA vs what's a separator.

# CRITICAL: Let me examine what "18 01 00 00" means at the end of every channel.
# It appears at the very end of EVERY channel's data.
# For InA: the FULL data from InA name to InB (including InB's record header):
# = 140 bytes. If record header is 4 bytes, InA's data = 140-4 = 136 bytes.
# 136 = 8(name) + 8(hdr) + 62(GEQ) + PEQ + tail
# We need to figure out tail size.

# For InB, the same: 140 bytes from InB name to InC, minus 4 = 136.

# Let me trace InA backwards from the end.
# InB record header starts at InB_name - 4 = 0x9c - 4 = 0x98
# InA data: offset 0x10 to 0x97 = 136 bytes

# At 0x90-0x97: 2c 01 00 00 18 01 00 00
# At 0x8e-0x8f: 00 00

# So the last 10 bytes of InA (before InB rec header) are:
# 00 00 | 2c 01 00 00 | 18 01 00 00
# These could be:
# [2B null/padding] [4B HPF: freq LE16 + slope LE16] [4B LPF: freq LE16 + slope LE16]
# HPF: freq=300 slope=0, LPF: freq=280 slope=0

# That leaves PEQ area: name+78 to name+125 (= offset 0x5e to 0x8d) = 48 bytes = 8 bands

# Let me verify: 8 PEQ bands starting at name+78
print("\n=== InA: 8 PEQ bands from name+78 ===")
ina = ch_pos['InA']
for band in range(8):
    pos = ina + 78 + band * 6
    gain = stream[pos] | (stream[pos+1] << 8)
    freq = stream[pos+2] | (stream[pos+3] << 8)
    q = stream[pos+4]
    typ = stream[pos+5]
    gain_db = (gain - 120) / 10.0
    print(f"  PEQ[{band}] name+{pos-ina:3d}: gain={gain:3d}({gain_db:+5.1f}dB) freq={freq:4d} Q={q:3d} type={typ}")

# After 8 PEQ: name+78+48 = name+126
print(f"\n  After PEQ: name+126")
print(f"  Remaining 10 bytes (HPF/LPF):")
for j in range(ina+126, ina+136):
    print(f"    name+{j-ina} [0x{j:04x}]: 0x{stream[j]:02x} ({stream[j]:3d})")

# That gives us: 00 00 2c 01 00 00 18 01 00 00
# Parse as:
tail = stream[ina+126:ina+136]
print(f"\n  Tail hex: {tail.hex(' ')}")
print(f"  [0:2]  = 0x{tail[0]|tail[1]<<8:04x} ({tail[0]|tail[1]<<8})")
print(f"  [2:4]  = 0x{tail[2]|tail[3]<<8:04x} ({tail[2]|tail[3]<<8})")
print(f"  [4:6]  = 0x{tail[4]|tail[5]<<8:04x} ({tail[4]|tail[5]<<8})")
print(f"  [6:8]  = 0x{tail[6]|tail[7]<<8:04x} ({tail[6]|tail[7]<<8})")
print(f"  [8:10] = 0x{tail[8]|tail[9]<<8:04x} ({tail[8]|tail[9]<<8})")

# ========================================================================
# Now let's do OUT1 with 9 PEQ bands hypothesis
# ========================================================================
print("\n=== Out1: 9 PEQ bands from name+24 ===")
out1 = ch_pos['Out1']
for band in range(9):
    pos = out1 + 24 + band * 6
    gain = stream[pos] | (stream[pos+1] << 8)
    freq = stream[pos+2] | (stream[pos+3] << 8)
    q = stream[pos+4]
    typ = stream[pos+5]
    gain_db = (gain - 120) / 10.0
    print(f"  PEQ[{band}] name+{pos-out1:3d}: gain={gain:3d}({gain_db:+5.1f}dB) freq={freq:4d} Q={q:3d} type={typ}")

# After 9 PEQ: name+24+54 = name+78
# Now look at the remaining bytes
print(f"\n  After PEQ (name+78):")
out2 = ch_pos['Out2']
out1_rec_end = out2 - 4  # before Out2's record header
for j in range(out1+78, out1_rec_end):
    print(f"    name+{j-out1} [0x{j:04x}]: 0x{stream[j]:02x} ({stream[j]:3d})")

# Out1 remaining from +78 to end: 00 00 31 00 f3 01 00 00 dc 00 31 00 f3 01 00 00 dc 00 18 01 00 00
# That's 22 bytes
# Parse:
print(f"\n  Remaining = {out1_rec_end - out1 - 78} bytes")

# Hmm, 22 bytes. Let me try:
# [2B pad/null] [8B limiter/compressor 1] [8B limiter/compressor 2] [4B level]
# Total: 2+8+8+4 = 22

# Or maybe: we have the wrong PEQ count
# Let me try with FEWER PEQ bands

# Actually, looking at Out3 which has clearly non-default values:
print("\n=== Out3: trying different PEQ counts ===")
out3 = ch_pos['Out3']
out4 = ch_pos['Out4']
out3_rec_end = out4 - 4

# Out3 data size from name: rec_end - name
out3_size = out3_rec_end - out3
print(f"Out3 data size: {out3_size} bytes")
# Name(8) + Flags(2) + Routing(8) + HPF/LPF(6) + PEQ(?) + Tail(?) = out3_size

# Out3 first 24 bytes:
# name+0..7:  Out3\0\0\0\0 (8 bytes)
# name+8..9:  05 00 (2 bytes flags)
# name+10..17: 18 01 18 01 18 01 18 01 (8 bytes routing)
# name+18..23: 7f 00 ee 00 0a 03 (6 bytes - this is the HPF/LPF or filter config)
#   LE16: 0x007f=127, 0x00ee=238, bytes: 0x0a=10, 0x03=3

# Let me try: maybe the 6 bytes at name+18..23 aren't HPF/LPF but are the FIRST PEQ band?
# PEQ[0]: gain=127(+0.7dB) freq=238 Q=10 type=3
# type=3 could be valid

# And then PEQ bands continue from name+24:
# name+24: 32 00 ba 00 1e 00 = gain=50(-7.0dB) freq=186 Q=30 type=0
# Hmm, wait. Is type=0 "parametric" and type=3 something else?

# The user says type is 0-8. Let me look at the OUT channels with default PEQ
# Out1 PEQ from +24: all type=0, Q=35
# The only non-type-0 I see is in Out3 at +18: type=3
# And Out2 at +22..23: 08 03 -> if part of HPF/LPF, the last 2 bytes are slope values

# WAIT. Let me reconsider the HPF/LPF structure.
# For Out1: +18..23 = 0b 00 3d 00 08 08
# Maybe: HPF_freq=0x000b=11, LPF_freq=0x003d=61, HPF_slope=8, LPF_slope=8
# For Out2: +18..23 = 3d 00 5b 00 08 03
# HPF=61, LPF=91, HPF_slope=8, LPF_slope=3
# For Out8: +18..23 = 00 00 2c 01 00 00
# HPF=0, LPF=300, HPF_slope=0, LPF_slope=0 (disabled)

# This makes sense! HPF=0 means off, LPF=300 means at max frequency (essentially off)
# Slope values 8=steep, 3=gentle, 0=off

# Now, for Out3: +18..23 = 7f 00 ee 00 0a 03
# HPF=127, LPF=238, HPF_slope=10, LPF_slope=3
# These are plausible filter values.

# So: outputs have 6B HPF/LPF at name+18, then PEQ starting at name+24.

# How many PEQ bands for outputs?
# Out1 data size: Out2 header at Out2-4 = 0x2a2
# Out1 at 0x240, so: 0x2a2 - 0x240 = 98 bytes
# 98 = 8(name) + 2(flags) + 8(routing) + 6(HPF/LPF) + PEQ + Tail
# 98 - 24 = 74 bytes for PEQ + Tail

# After PEQ we have the tail. For outputs, the tail pattern is:
# 00 00 31 00 f3 01 00 00 dc 00 31 00 f3 01 00 00 dc 00 18 01 00 00
# Let me count: that's 22 bytes

# PEQ = 74 - 22 = 52 bytes... 52/6 = 8.67 -> not evenly divisible!

# Hmm. Let me recount more carefully.
print(f"\n=== Precise Out1 boundary ===")
print(f"Out1 name: 0x{out1:04x}")
print(f"Out2 name: 0x{out2:04x}")
# Record header before Out2 = 4 bytes: 00 00 01 00
# These are at Out2-4 to Out2-1
print(f"Out2 rec hdr at: 0x{out2-4:04x} to 0x{out2-1:04x}")
print(f"  = {stream[out2-4:out2].hex(' ')}")
print(f"Out1 record data: 0x{out1:04x} to 0x{out2-4:04x} = {out2-4-out1} bytes")

# OK so Out1 record = 102 bytes.  Wait that's different from what I computed before.
# Let me recheck: Out1 at 0x240, Out2 at 0x2a6
# Out2 - 4 = 0x2a2
# 0x2a2 - 0x240 = 0x62 = 98 bytes.
# But earlier I printed "Out1: 0x0240 ( 574), size to next = 104"
# 104 = name-to-name = Out2(0x2a6) - Out1(0x240) = 0x66 = 102. Hmm, 102 != 104.
# Wait, in the second analysis (length-corrected), Out2 was at 0x2a6.
# 0x2a6 - 0x240 = 0x66 = 102.
# But first analysis said 105. The length correction matters.

# Let me just use the corrected offsets.
# Out1=0x240, Out2=0x2a6: diff=102
# Record header = 4 bytes, so Out1 data = 102 - 4 = 98 bytes

# 98 bytes = 8(name) + 2(flags) + 8(routing) + 6(HPF/LPF) + PEQ + tail
# = 24 + PEQ + tail = 98
# PEQ + tail = 74

# Out1 tail (working backwards):
# Last 4 bytes: 18 01 00 00 (always present)
# Before that: 31 00 f3 01 00 00 dc 00 (8 bytes - filter block)
# Before that: 31 00 f3 01 00 00 dc 00 (8 bytes - duplicate)
# Before that: 00 00 (2 bytes - separator)
# Tail total = 4 + 8 + 8 + 2 = 22 bytes
# PEQ = 74 - 22 = 52 bytes -> NOT divisible by 6!

# Something's off. Let me verify by looking at exact bytes.
print(f"\n=== Out1 exact bytes from +24 to end of record ===")
for j in range(out1+24, out2-4):
    rel = j - out1
    print(f"  name+{rel:3d} [0x{j:04x}]: 0x{stream[j]:02x} ({stream[j]:3d})")

# Count these bytes
n = (out2 - 4) - (out1 + 24)
print(f"\nBytes from name+24 to record end: {n}")
print(f"{n} / 6 = {n/6:.2f}")

# Let's see... 74 bytes. 74/6 = 12.33. Not even.
# But what if the "00 00" at +78 is actually the LAST 2 bytes of the 9th PEQ band?
# The 9th PEQ band would be: gain=120 freq=285 Q=35 type=0 at +72..77
# Then +78: 00 00 - NOT a PEQ band start
# But what if there are actually more PEQ bands?

# Let me try treating ALL 74 bytes as 6-byte PEQ + remaining:
print(f"\n=== Out1: parsing ALL post-filter bytes as PEQ ===")
pos = out1 + 24
band = 0
end = out2 - 4
while pos + 6 <= end:
    gain = stream[pos] | (stream[pos+1] << 8)
    freq = stream[pos+2] | (stream[pos+3] << 8)
    q = stream[pos+4]
    typ = stream[pos+5]
    gain_db = (gain - 120) / 10.0
    marker = ""
    if gain > 240 or typ > 8:
        marker = " <-- SUSPECT"
    print(f"  PEQ[{band:2d}] name+{pos-out1:3d}: gain={gain:3d}({gain_db:+5.1f}dB) freq={freq:4d} Q={q:3d} type={typ}{marker}")
    pos += 6
    band += 1
print(f"  Remaining bytes: {end - pos}")
for j in range(pos, end):
    print(f"    [0x{j:04x}]: 0x{stream[j]:02x}")

# Now let me also try: what if the record header is NOT 4 bytes but 6 bytes?
# [00 00 00 00 ch_id LE16] = 6 bytes
# Then Out1 data = 102 - 6 = 96 bytes
# 96 - 24(header) = 72 bytes for PEQ + tail
# 72/6 = 12 PEQ bands (no tail!)

# OR: what if the '18 01 00 00' at the end is part of the NEXT channel's header?
# Then the record header would be: [18 01] [00 00] [00 00] [ch_id] = 8 bytes
# Out1 data = 102 - 8 = 94... not great

# Let me try 6-byte record header: [00 00] [00 00] [ch_id LE16]
# Then for InB: at InB_name - 6, we should have: XX XX 00 00 01 00
# InB at 0x9c, InB-6 = 0x96
print(f"\n=== Testing 6-byte record header ===")
for name, off in sorted_chs:
    if off >= 6:
        hdr = stream[off-6:off]
        print(f"  {name:>5s} name-6: {hdr.hex(' ')}")

# Results show: ... 18 01 00 00 00 00 01 00 for InB at name-8
# So 6-byte header would be: 00 00 00 00 01 00 (with 18 01 being end of prev channel)
# That means: [padding 00 00] [padding 00 00] [ch_id LE16]

# With 6-byte header:
# InA data (no header since first): name to InB_name - 6 = 0x10 to 0x96 = 134 bytes
# 134 = 8(name) + 8(header) + 62(GEQ) + 48(8 PEQ) + 8(tail)
# tail = 134 - 8 - 8 - 62 - 48 = 8 bytes
# InA name+126 to name+133: 00 00 2c 01 00 00 18 01
# = 0, 300, 0, 280
# That could be: [2B HPF_freq] [2B HPF_slope] [2B LPF_freq] [2B LPF_slope]
# HPF=0(off), slope=300(?), LPF=0(off), slope=280(?)
# Or: [2B null] [2B HPF_freq=300] [2B null] [2B LPF_freq=280]

# Alternatively with 6-byte header, Out1 data:
# Out1 to Out2 - 6 = 0x240 to 0x2a0 = 96 bytes
# 96 = 8(name) + 2(flags) + 8(routing) + 6(HPF/LPF) + ? = 24 + 72
# 72 / 6 = 12 PEQ bands exactly!

print("\n=== Testing with 6-byte record header: Out1 has 12 PEQ bands? ===")
out1_data_end_v2 = out2 - 6
print(f"Out1 data: 0x{out1:04x} to 0x{out1_data_end_v2:04x} = {out1_data_end_v2-out1} bytes")
for band in range(12):
    pos = out1 + 24 + band * 6
    if pos + 6 > out1_data_end_v2:
        print(f"  PEQ[{band}] would exceed boundary!")
        break
    gain = stream[pos] | (stream[pos+1] << 8)
    freq = stream[pos+2] | (stream[pos+3] << 8)
    q = stream[pos+4]
    typ = stream[pos+5]
    gain_db = (gain - 120) / 10.0
    print(f"  PEQ[{band:2d}] name+{pos-out1:3d}: gain={gain:3d}({gain_db:+5.1f}dB) freq={freq:4d} Q={q:3d} type={typ}")

# Now check: with 6-byte header, InA has:
# Data = InB_name - 6 - InA_name = 0x96 - 0x10 = 134 bytes
# 134 = 8(name) + 8(header) + 62(GEQ) + PEQ + HPF/LPF
# PEQ + HPF/LPF = 134 - 78 = 56 bytes
# If 8 PEQ: 48 + 8(HPF/LPF) = 56. Perfect!
# HPF/LPF = 8 bytes: 00 00 2c 01 00 00 18 01
# = [2B:0] [2B:300] [2B:0] [2B:280]

print("\n=== Testing with 6-byte record header: InA ===")
ina_data_end_v2 = ch_pos['InB'] - 6
print(f"InA data: 0x{ina:04x} to 0x{ina_data_end_v2:04x} = {ina_data_end_v2-ina} bytes")
# 8 PEQ from name+78 = 48 bytes -> name+126
# Remaining: name+126 to name+134 = 8 bytes
tail = stream[ina+126:ina_data_end_v2]
print(f"Tail (8 bytes): {tail.hex(' ')}")
# Parse as 4x LE16:
for k in range(0, len(tail), 2):
    v = tail[k] | (tail[k+1] << 8)
    print(f"  [{k}:{k+2}] = 0x{v:04x} ({v})")

# ========================================================================
# FINAL VERIFICATION: Check Out3 with 12 PEQ bands
# ========================================================================
print("\n=== Out3 with 12 PEQ bands (6B record header) ===")
out3_data_end_v2 = out4 - 6
print(f"Out3 data: 0x{out3:04x} to 0x{out3_data_end_v2:04x} = {out3_data_end_v2-out3} bytes")
for band in range(12):
    pos = out3 + 24 + band * 6
    if pos + 6 > out3_data_end_v2:
        print(f"  PEQ[{band}] exceeds boundary!")
        break
    gain = stream[pos] | (stream[pos+1] << 8)
    freq = stream[pos+2] | (stream[pos+3] << 8)
    q = stream[pos+4]
    typ = stream[pos+5]
    gain_db = (gain - 120) / 10.0
    print(f"  PEQ[{band:2d}] name+{pos-out3:3d}: gain={gain:3d}({gain_db:+5.1f}dB) freq={freq:4d} Q={q:3d} type={typ}")

# ========================================================================
# COMPARE: Input and Output tail/filter data for ALL channels
# ========================================================================
print("\n=== INPUT CHANNEL HPF/LPF (8 bytes at end of record, 6B rec header) ===")
for name in ['InA', 'InB', 'InC', 'InD']:
    off = ch_pos[name]
    idx = ch_names.index(name)
    # Find next channel
    nxt_idx = sorted_chs.index((name, off))
    if nxt_idx + 1 < len(sorted_chs):
        nxt_off = sorted_chs[nxt_idx+1][1]
    else:
        nxt_off = len(stream)
    data_end = nxt_off - 6
    tail = stream[data_end-8:data_end] if data_end >= off + 134 else stream[off+126:off+134]
    # Actually, for inputs: name+126 to name+133 (8 bytes)
    t = stream[off+126:off+134]
    vals = [t[k] | (t[k+1] << 8) for k in range(0, 8, 2)]
    print(f"  {name}: {t.hex(' ')} -> LE16 = {[f'0x{v:04x}({v})' for v in vals]}")

print("\n=== OUTPUT CHANNEL DATA AFTER 12 PEQ BANDS (should be empty/just reaches end) ===")
for name in ['Out1', 'Out2', 'Out3', 'Out4', 'Out5', 'Out6', 'Out7', 'Out8']:
    off = ch_pos[name]
    nxt_idx = [i for i, (n, o) in enumerate(sorted_chs) if n == name][0]
    if nxt_idx + 1 < len(sorted_chs):
        nxt_off = sorted_chs[nxt_idx+1][1]
        data_end = nxt_off - 6
    else:
        data_end = off + 96  # estimate for last channel
    peq_end = off + 24 + 12 * 6  # name+96
    remaining = data_end - peq_end
    if remaining > 0:
        rem_data = stream[peq_end:data_end]
        print(f"  {name}: {remaining} bytes remaining after 12 PEQ: {rem_data.hex(' ')}")
    elif remaining == 0:
        print(f"  {name}: exactly 0 bytes remaining (perfect fit!)")
    else:
        print(f"  {name}: {remaining} bytes (OVERFLOW!)")
