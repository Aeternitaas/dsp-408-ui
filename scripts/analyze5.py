#!/usr/bin/env python3
"""Final analysis: determine exact PEQ count and post-PEQ structures."""

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

ch_pos = {}
for name in ['InA', 'InB', 'InC', 'InD', 'Out1', 'Out2', 'Out3', 'Out4', 'Out5', 'Out6', 'Out7', 'Out8']:
    ch_pos[name] = stream.find(name.encode())

# ========================================================================
# FINAL ANALYSIS
#
# Key finding from previous analysis:
# - Record header before each channel (except InA): 4 bytes [00 00] [ch_id LE16]
# - ALL records end with [18 01] [00 00] just before the next record header
# - Input records: 136 bytes from name to next record header
# - Output records: 100 bytes from name to next record header
#
# For INPUTS (136 bytes total):
#   [8B name] [8B header] [62B GEQ] [48B PEQ=8*6] [10B filters/tail]
#   = 8 + 8 + 62 + 48 + 10 = 136
#
# For OUTPUTS (100 bytes total):
#   [8B name] [2B flags] [8B routing] [6B HPF/LPF] [54B PEQ=9*6] [22B filters/tail]
#   = 8 + 2 + 8 + 6 + 54 + 22 = 100
#
# The "tail" for outputs: 00 00 | 31 00 f3 01 00 00 dc 00 | 31 00 f3 01 00 00 dc 00 | 18 01 00 00
#
# But PEQ[9-11] had bad values when treating as 12 PEQ bands.
# So: 9 PEQ bands for outputs, and the remaining 22 bytes are post-PEQ structures.
#
# Now let me figure out what PEQ "band 9" would look like vs filter data.
# Out1 at name+78 after 9 PEQ: 00 00 31 00 f3 01 00 00 dc 00 31 00 f3 01 00 00 dc 00 18 01 00 00
# Out3 at name+78: 00 00 31 00 f3 01 00 00 dc 00 31 00 f3 01 00 00 dc 00 18 01 00 00
# These are IDENTICAL for Out1 and Out3 (and probably all outputs).
# Since Out3 has very different PEQ values but the same tail, this is clearly
# NOT PEQ data - it's a fixed structure (limiter/compressor/delay/etc.)
# ========================================================================

# Let me verify the tail is identical for ALL output channels
print("=== OUTPUT CHANNEL TAILS (22 bytes after 9 PEQ bands) ===")
for name in ['Out1', 'Out2', 'Out3', 'Out4', 'Out5', 'Out6', 'Out7', 'Out8']:
    off = ch_pos[name]
    tail_start = off + 24 + 9*6  # name+78
    tail = stream[tail_start:tail_start+22]
    print(f"  {name}: {tail.hex(' ')}")

# Verify: tail for InA (10 bytes after 8 PEQ)
print("\n=== INPUT CHANNEL TAILS (10 bytes after 8 PEQ bands) ===")
for name in ['InA', 'InB', 'InC', 'InD']:
    off = ch_pos[name]
    tail_start = off + 78 + 8*6  # name+126
    tail = stream[tail_start:tail_start+10]
    print(f"  {name}: {tail.hex(' ')}")

# ========================================================================
# PARSE THE TAIL STRUCTURES
# ========================================================================
print("\n" + "="*80)
print("=== INPUT TAIL STRUCTURE (10 bytes) ===")
print("="*80)
# InA tail: 00 00 2c 01 00 00 18 01 00 00
# Parse as LE16 words: 0x0000, 0x012c(300), 0x0000, 0x0118(280), 0x0000
# Hypothesis: [2B HPF_freq] [2B HPF_slope_or_type] [2B LPF_freq] [2B LPF_slope_or_type] [2B ??]
# Wait that's 5 words = 10 bytes. Not right for filter pairs.
# Alternative: [2B null/separator] [4B HPF: freq+type] [4B LPF: freq+type]
# = [00 00] [2c 01 = freq 300] [00 00 = type 0] [18 01 = freq 280] [00 00 = type 0]

# For HPF/LPF freq encoding, using the same (val-120)/10 formula:
# 300: (300-120)/10 = 18.0 dB? That makes no sense for frequency.
# Maybe the freq encoding is different for HPF/LPF.
# Or 300 maps to frequency directly (e.g., 300 = 30.0 Hz? Or some log scale?)

# Let me check what Out8 HPF/LPF at name+18..23 looks like:
# Out8: 00 00 2c 01 00 00 = HPF=0, LPF=300, slope=0
# And InA tail has the same pattern!
# So the input tail and output HPF/LPF use the same encoding.

# ========================================================================
# Parse output tail structure
# ========================================================================
print("\n" + "="*80)
print("=== OUTPUT TAIL STRUCTURE (22 bytes) ===")
print("="*80)
# 00 00 | 31 00 f3 01 00 00 dc 00 | 31 00 f3 01 00 00 dc 00 | 18 01 00 00
# [2B null] [8B block A] [8B block B] [4B level]
# Block: [31 00] [f3 01] [00 00] [dc 00]
#       = LE16: 49, 499, 0, 220
# The two blocks are identical -> possibly stereo pair or some redundancy

# Let me check if these change across channels
print("Output tail blocks:")
for name in ['Out1', 'Out2', 'Out3', 'Out4', 'Out5', 'Out6', 'Out7', 'Out8']:
    off = ch_pos[name]
    tail = stream[off+78:off+100]
    # Split: [2B] [8B] [8B] [4B]
    sep = tail[0:2]
    blk_a = tail[2:10]
    blk_b = tail[10:18]
    lvl = tail[18:22]
    # Parse blocks as 4x LE16
    def parse_block(b):
        return [b[i]|b[i+1]<<8 for i in range(0,len(b),2)]
    a = parse_block(blk_a)
    b_vals = parse_block(blk_b)
    l = parse_block(lvl)
    same = "SAME" if blk_a == blk_b else "DIFF"
    print(f"  {name}: sep={sep.hex()} blkA={a} blkB={b_vals} [{same}] lvl={l}")

# ========================================================================
# COMPLETE STRUCTURE SUMMARY
# ========================================================================
print("\n" + "="*80)
print("=== COMPLETE PER-CHANNEL DATA STRUCTURE ===")
print("="*80)

print("""
GLOBAL HEADER (16 bytes, offset 0x0000):
  [2B]  Flags/version:       0xFFFF
  [14B] Scene name:          ASCII, null/space padded

INPUT CHANNEL RECORD (140 bytes total: 4B header + 136B data):
  Record header [4B]:
    [2B] Padding:            0x0000
    [2B] Channel bitmask:    LE16 (InA=0, InB=1, InC=2, InD=4)
         Note: InA is first record, its header is the global header instead

  Channel data [136B]:
    Name [8B]:
      [3-4B] Channel name:   ASCII ("InA", "InB", "InC", "InD")
      [4-5B] Null padding:   0x00 bytes to fill 8 bytes

    Header [8B] (name+8):
      [2B] Unknown1:         LE16 (always 0x0000 for inputs)
      [2B] Level1:           LE16 (99 = 0x0063 for all inputs)
      [2B] Level2:           LE16 (99 = 0x0063 for all inputs)
      [2B] Unknown2:         LE16 (always 0x0000 for inputs)

    GEQ [62B] (name+16):
      31 bands x 2 bytes each (LE16)
      Encoding: dB = (value - 120) / 10.0
      0x0078 (120) = 0.0 dB

    PEQ [48B] (name+78):
      8 bands x 6 bytes each:
        [2B] Gain:           LE16, encoding: dB = (value - 120) / 10.0
        [2B] Frequency:      LE16, encoding TBD (device-specific freq table index?)
        [1B] Q:              0-255
        [1B] Type:           0-8 (0=parametric, others TBD)

    HPF/LPF [10B] (name+126):
      [2B] HPF frequency:    LE16 (0 = off)
      [2B] HPF slope/type:   LE16 (0 = off, 300 = max?)
      [2B] LPF frequency:    LE16 (0 = off)
      [2B] LPF slope/type:   LE16 (0 = off, 280 = ??)
      [2B] Padding:          LE16 (always 0x0000)

OUTPUT CHANNEL RECORD (104 bytes total: 4B header + 100B data):
  Record header [4B]:
    [2B] Padding:            0x0000
    [2B] Channel bitmask:    LE16 (Out1=8, Out2=1, Out3=2, Out4=4,
                                    Out5=8, Out6=16, Out7=32, Out8=64)

  Channel data [100B]:
    Name [8B]:
      [4B] Channel name:     ASCII ("Out1" through "Out8")
      [4B] Null padding:     0x00

    Flags [2B] (name+8):
      [2B] Config flags:     LE16 (varies: 5, 10, 15)

    Source Routing [8B] (name+10):
      [2B] Source 1 level:   LE16 (0x0118 = 280)
      [2B] Source 2 level:   LE16 (0x0118 = 280)
      [2B] Source 3 level:   LE16 (0x0118 = 280)
      [2B] Source 4 level:   LE16 (0x0118 = 280)

    HPF/LPF [6B] (name+18):
      [2B] HPF frequency:    LE16
      [2B] LPF frequency:    LE16
      [1B] HPF slope:        0-255 (0=off, 8=steep, etc.)
      [1B] LPF slope:        0-255 (0=off, 3=gentle, 8=steep, etc.)

    PEQ [54B] (name+24):
      9 bands x 6 bytes each:
        [2B] Gain:           LE16, encoding: dB = (value - 120) / 10.0
        [2B] Frequency:      LE16
        [1B] Q:              0-255
        [1B] Type:           0-8

    Post-PEQ tail [22B] (name+78):
      [2B] Null separator:   0x0000
      [8B] Limiter block A:
        [2B] Threshold?:     LE16 (49)
        [2B] Ratio?:         LE16 (499)
        [2B] Attack?:        LE16 (0)
        [2B] Release?:       LE16 (220)
      [8B] Limiter block B:  (duplicate of block A)
        [2B] Threshold?:     LE16 (49)
        [2B] Ratio?:         LE16 (499)
        [2B] Attack?:        LE16 (0)
        [2B] Release?:       LE16 (220)
      [4B] Output level:
        [2B] Level:          LE16 (0x0118 = 280)
        [2B] Padding:        0x0000

GLOBAL TRAILER (after Out8 record):
  Remaining bytes contain global routing/config data.
""")

# ========================================================================
# VERIFY ALL CHANNELS
# ========================================================================
print("="*80)
print("=== VERIFICATION: ALL INPUT CHANNELS ===")
print("="*80)
for name in ['InA', 'InB', 'InC', 'InD']:
    off = ch_pos[name]
    print(f"\n--- {name} at 0x{off:04x} ---")

    # Name
    nm = stream[off:off+8]
    print(f"  Name: {nm.hex(' ')} = '{nm[:4].decode('latin-1').rstrip(chr(0))}'")

    # Header
    hdr = stream[off+8:off+16]
    h_words = [hdr[i]|hdr[i+1]<<8 for i in range(0,8,2)]
    print(f"  Header: {hdr.hex(' ')} -> {h_words}")

    # GEQ (just show non-zero)
    print("  GEQ non-0dB bands:")
    for b in range(31):
        p = off + 16 + b*2
        v = stream[p] | (stream[p+1] << 8)
        if v != 120:
            print(f"    Band {b}: {v} ({(v-120)/10.0:+.1f} dB)")

    # PEQ
    print("  PEQ bands:")
    for b in range(8):
        p = off + 78 + b*6
        gain = stream[p]|stream[p+1]<<8
        freq = stream[p+2]|stream[p+3]<<8
        q = stream[p+4]
        typ = stream[p+5]
        marker = " *" if gain != 120 or freq == 0 else ""
        print(f"    [{b}] gain={gain:3d}({(gain-120)/10.0:+5.1f}dB) freq={freq:4d} Q={q:3d} type={typ}{marker}")

    # Filters
    flt = stream[off+126:off+136]
    fw = [flt[i]|flt[i+1]<<8 for i in range(0,10,2)]
    print(f"  HPF/LPF: {flt.hex(' ')} -> {fw}")

print("\n" + "="*80)
print("=== VERIFICATION: ALL OUTPUT CHANNELS ===")
print("="*80)
for name in ['Out1', 'Out2', 'Out3', 'Out4', 'Out5', 'Out6', 'Out7', 'Out8']:
    off = ch_pos[name]
    print(f"\n--- {name} at 0x{off:04x} ---")

    # Name
    nm = stream[off:off+8]
    print(f"  Name: {nm.hex(' ')} = '{nm[:4].decode('latin-1')}'")

    # Flags
    flags = stream[off+8]|stream[off+9]<<8
    print(f"  Flags: 0x{flags:04x} ({flags})")

    # Routing
    routing = [stream[off+10+i]|stream[off+11+i]<<8 for i in range(0,8,2)]
    print(f"  Routing: {routing}")

    # HPF/LPF
    hpf_freq = stream[off+18]|stream[off+19]<<8
    lpf_freq = stream[off+20]|stream[off+21]<<8
    hpf_slope = stream[off+22]
    lpf_slope = stream[off+23]
    print(f"  HPF: freq={hpf_freq} slope={hpf_slope}")
    print(f"  LPF: freq={lpf_freq} slope={lpf_slope}")

    # PEQ
    print("  PEQ bands:")
    for b in range(9):
        p = off + 24 + b*6
        gain = stream[p]|stream[p+1]<<8
        freq = stream[p+2]|stream[p+3]<<8
        q = stream[p+4]
        typ = stream[p+5]
        marker = " *" if gain != 120 else ""
        print(f"    [{b}] gain={gain:3d}({(gain-120)/10.0:+5.1f}dB) freq={freq:4d} Q={q:3d} type={typ}{marker}")

    # Post-PEQ tail
    tail = stream[off+78:off+100]
    print(f"  Post-PEQ: {tail.hex(' ')}")
    sep = tail[0]|tail[1]<<8
    blk_a = [tail[2+i]|tail[3+i]<<8 for i in range(0,8,2)]
    blk_b = [tail[10+i]|tail[11+i]<<8 for i in range(0,8,2)]
    lvl = tail[18]|tail[19]<<8
    pad = tail[20]|tail[21]<<8
    print(f"    Sep={sep}, BlkA={blk_a}, BlkB={blk_b}, Level={lvl}, Pad={pad}")

# Global trailer
print("\n" + "="*80)
print("=== GLOBAL TRAILER ===")
print("="*80)
out8 = ch_pos['Out8']
trailer_start = out8 + 100  # After Out8's 100-byte data
trailer = stream[trailer_start:]
print(f"Trailer ({len(trailer)} bytes at 0x{trailer_start:04x}):")
for i in range(0, len(trailer), 2):
    if i+1 < len(trailer):
        w = trailer[i]|trailer[i+1]<<8
        print(f"  +{i:3d}: 0x{w:04x} ({w})")

# ========================================================================
# STREAM OFFSET TABLE
# ========================================================================
print("\n" + "="*80)
print("=== COMPLETE STREAM OFFSET TABLE ===")
print("="*80)
print(f"{'Description':<40s} {'Offset':>10s} {'Size':>6s}")
print(f"{'='*40} {'='*10} {'='*6}")
print(f"{'Global header (flags+scene name)':<40s} {'0x0000':>10s} {'16':>6s}")
print()

for name in ['InA', 'InB', 'InC', 'InD']:
    off = ch_pos[name]
    rec_off = off - 4 if name != 'InA' else off
    if name != 'InA':
        print(f"{f'{name} record header':<40s} {'0x{:04x}'.format(rec_off):>10s} {'4':>6s}")
    print(f"{f'{name} name':<40s} {'0x{:04x}'.format(off):>10s} {'8':>6s}")
    print(f"{f'{name} channel header':<40s} {'0x{:04x}'.format(off+8):>10s} {'8':>6s}")
    print(f"{f'{name} GEQ (31 bands)':<40s} {'0x{:04x}'.format(off+16):>10s} {'62':>6s}")
    print(f"{f'{name} PEQ (8 bands)':<40s} {'0x{:04x}'.format(off+78):>10s} {'48':>6s}")
    print(f"{f'{name} HPF/LPF filters':<40s} {'0x{:04x}'.format(off+126):>10s} {'10':>6s}")
    print()

for name in ['Out1', 'Out2', 'Out3', 'Out4', 'Out5', 'Out6', 'Out7', 'Out8']:
    off = ch_pos[name]
    rec_off = off - 4
    print(f"{f'{name} record header':<40s} {'0x{:04x}'.format(rec_off):>10s} {'4':>6s}")
    print(f"{f'{name} name':<40s} {'0x{:04x}'.format(off):>10s} {'8':>6s}")
    print(f"{f'{name} flags':<40s} {'0x{:04x}'.format(off+8):>10s} {'2':>6s}")
    print(f"{f'{name} source routing (4 levels)':<40s} {'0x{:04x}'.format(off+10):>10s} {'8':>6s}")
    print(f"{f'{name} HPF/LPF (freq+slope)':<40s} {'0x{:04x}'.format(off+18):>10s} {'6':>6s}")
    print(f"{f'{name} PEQ (9 bands)':<40s} {'0x{:04x}'.format(off+24):>10s} {'54':>6s}")
    print(f"{f'{name} post-PEQ (limiter+level)':<40s} {'0x{:04x}'.format(off+78):>10s} {'22':>6s}")
    print()

out8 = ch_pos['Out8']
print(f"{'Global trailer':<40s} {'0x{:04x}'.format(out8+100):>10s} {f'{len(stream)-out8-100}':>6s}")
