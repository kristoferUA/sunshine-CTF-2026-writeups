#!/usr/bin/env python3
"""Recover the IntMod input from the decoded VM constraints."""

MOD = 65521
MASK64 = (1 << 64) - 1

PROGRAM = bytes.fromhex(
    '0000000000010007000000000000000001000000020002000000000000000000020000000300000087caeb85b179379e03000000040001130000000000000000'
    '04000000010300000000000000000000000000000300020d00000000000000000100000004030000000000000000000002000000010000004febd4273daeb2c2'
    '030000000200001f000000000000000004000000000102000000000000000000000000000104001d000000000000000001000000030101000000000000000000'
    '0200000002000000f979379eb1675616030000000000010b000000000000000004000000040200000000000000000000000000000402012b0000000000000000'
    '01000000000400000000000000000000020000000300000063aeb2c277caeb850300000001000017000000000000000004000000020301000000000000000000'
    '00000000020300110000000000000000010000000102010000000000000000000200000000000000c56756162febd42703000000040001250000000000000000'
    '0400000003000000000000000000000000000000000201050000000000000000010000000400000000000000000000000200000001000000eb113113bb49d094'
    '030000000300002f0000000000000000040000000201010000000000000000000000000004010029000000000000000001000000030401000000000000000000'
    '0200000000000000b9e5e41c6d4758bf030000000200010900000000000000000400000001000000000000000000000000000000020001170000000000000000'
    '01000000010200000000000000000000020000000400000093fd5966b8fee8d60300000003000035000000000000000004000000000401000000000000000000'
    '000000000103001f00000000000000000100000000010100000000000000000002000000040000002f64bd78641d76a003000000020001070000000000000000'
    '04000000030400000000000000000000000000000304010b0000000000000000010000000203000000000000000000000200000001000000db28b4a0d17e03e7'
    '03000000000000270000000000000000040000000401010000000000000000000000000000040025000000000000000001000000030001000000000000000000'
    '0200000002000000e3c6889cf06abc8e030000000100011100000000000000000400000004020000000000000000000000000000020101130000000000000000'
    '010000000402000000000000000000000200000003000000c34c3775cc659958030000000000002b000000000000000004000000010301000000000000000000'
    '000000000403002f00000000000000000100000001040100000000000000000002000000000000004f127dc4274e8e1d030000000200010d0000000000000000'
    '040000000300000000000000000000000000000001000103000000000000000001000000020100000000000000000000020000000400000065d155b4caac44eb'
    '030000000300001d0000000000000000040000000004010000000000000000000000000003020035000000000000000001000000000301000000000000000000'
    '0200000001000000692d38eb08eadf9d0300000004000115000000000000000004000000020100000000000000000000000000000003011b0000000000000000'
    '01000000020000000000000000000000020000000400000023c3b5929627bcc60300000001000031000000000000000004000000030401000000000000000000'
    '000000000400000900000000000000000100000003040100000000000000000002000000010000006521ae75910b4fdb03000000020001230000000000000000'
    '04000000000100000000000000000000000000000204012d00000000000000000100000001020000000000000000000002000000030000005f61a4033356e0bb'
    '030000000000000f000000000000000004000000040301000000000000000000'
)

HASHES = (
    (10025, 54966, 33635),
    (22888, 7921, 53274),
    (23294, 18869, 60217),
    (45273, 35532, 46459),
    (63285, 36338, 6954),
    (34628, 11208, 54581),
    (1940, 48303, 36828),
    (49799, 60871, 28292),
    (37534, 57791, 11810),
    (54116, 45832, 62698),
    (58200, 37146, 4596),
    (27510, 59177, 51630),
    (18853, 35663, 15785),
    (2862, 23582, 58635),
    (12700, 9185, 4024),
    (64762, 34290, 15599),
    (45270, 49642, 1620),
    (53086, 53271, 22554),
    (48645, 27692, 49481),
    (7691, 62087, 22097),
    (16290, 2185, 10425),
    (7420, 46502, 52612),
    (22519, 11413, 50086),
    (27383, 58802, 47815),
    (53634, 59972, 44444),
    (23942, 17312, 46654),
    (16486, 51856, 16967),
    (50558, 22907, 59945),
    (51730, 10593, 20495),
    (20447, 3348, 60497),
    (2839, 14185, 16780),
    (48993, 33574, 52257),
    (6479, 6429, 59784),
    (58196, 25773, 14730),
    (16209, 60311, 45609),
    (61653, 13635, 55101),
    (30029, 31955, 19089),
    (14661, 43714, 61917),
    (14406, 65416, 40826),
    (38799, 57786, 8749),
)


def decode(ins):
    return (int.from_bytes(ins[0:4], "little"), ins[4], ins[5], ins[6], ins[7],
            int.from_bytes(ins[8:16], "little"))

def rol(value, count):
    count &= 63
    return ((value << count) | (value >> ((64 - count) & 63))) & MASK64

def ror(value, count):
    count &= 63
    return ((value >> count) | (value << ((64 - count) & 63))) & MASK64

def recover_state_bytes():
    if len(PROGRAM) != 90 * 16 or len(HASHES) != 40:
        raise ValueError("embedded VM data has an unexpected size")

    # Horner evaluation over reversed bytes gives coefficient base**j to byte j.
    matrix = []
    for seed, addend, expected in HASHES:
        base = seed % MOD
        rhs = (expected + addend) % MOD
        matrix.append([pow(base, j, MOD) for j in range(40)] + [rhs])

    # Gauss-Jordan elimination in F_65521.
    pivot_rows = []
    row = 0
    for col in range(40):
        pivot = next((i for i in range(row, len(matrix))
                      if matrix[i][col] % MOD), None)
        if pivot is None:
            continue
        matrix[row], matrix[pivot] = matrix[pivot], matrix[row]
        inverse = pow(matrix[row][col], MOD - 2, MOD)
        matrix[row] = [(value * inverse) % MOD for value in matrix[row]]
        for i in range(len(matrix)):
            if i == row:
                continue
            factor = matrix[i][col] % MOD
            if factor:
                matrix[i] = [(x - factor * y) % MOD
                             for x, y in zip(matrix[i], matrix[row])]
        pivot_rows.append((row, col))
        row += 1

    for equation in matrix:
        if all(value % MOD == 0 for value in equation[:40]) and equation[40] % MOD:
            raise ValueError("modular constraints are inconsistent")
    if len(pivot_rows) != 40:
        raise ValueError(f"constraint matrix has rank {len(pivot_rows)}, expected 40")

    result = [0] * 40
    for pivot_row, col in pivot_rows:
        result[col] = matrix[pivot_row][40] % MOD
    if any(value > 255 for value in result):
        raise ValueError("solution contains a value outside the byte range")
    return bytes(result)

def undo_arx(state_bytes):
    state = [int.from_bytes(state_bytes[i:i + 8], "little")
             for i in range(0, 40, 8)]

    # The operations are inverted in reverse execution order.
    for pc in range(89, -1, -1):
        op, a, b, _index, rotation, immediate = decode(PROGRAM[pc * 16:(pc + 1) * 16])
        if op == 0:
            state[a] = (state[a] - rol(state[b], rotation)) & MASK64
        elif op == 1:
            state[a] ^= rol(state[b], rotation)
        elif op == 2:
            if immediate & 1 == 0:
                raise ValueError(f"even multiplier at instruction {pc}")
            state[a] = (state[a] * pow(immediate, -1, 1 << 64)) & MASK64
        elif op == 3:
            state[a] = ror(state[a], rotation)
        elif op == 4:
            state[a], state[b] = state[b], state[a]
        else:
            raise ValueError(f"unexpected opcode {op} at instruction {pc}")
    return b"".join(value.to_bytes(8, "little") for value in state)

def check_recovery(state_bytes, original):
    # Re-evaluate every modular comparison.
    for seed, addend, expected in HASHES:
        accumulator = 0
        for value in reversed(state_bytes):
            accumulator = (accumulator * (seed % MOD) + value) % MOD
        if (accumulator - addend) % MOD != expected:
            raise ValueError("forward hash check failed")

    # Replay the reversible prefix from the recovered input.
    replay = [int.from_bytes(original[i:i + 8], "little")
              for i in range(0, 40, 8)]
    for pc in range(90):
        op, a, b, _index, rotation, immediate = decode(PROGRAM[pc * 16:(pc + 1) * 16])
        if op == 0:
            replay[a] = (replay[a] + rol(replay[b], rotation)) & MASK64
        elif op == 1:
            replay[a] ^= rol(replay[b], rotation)
        elif op == 2:
            replay[a] = (replay[a] * immediate) & MASK64
        elif op == 3:
            replay[a] = rol(replay[a], rotation)
        elif op == 4:
            replay[a], replay[b] = replay[b], replay[a]
        else:
            raise ValueError(f"unexpected opcode {op} at instruction {pc}")
    encoded = b"".join(value.to_bytes(8, "little") for value in replay)
    if encoded != state_bytes:
        raise ValueError("forward ARX check failed")

def main():
    state_bytes = recover_state_bytes()
    original = undo_arx(state_bytes)
    check_recovery(state_bytes, original)

    padding = b"\x07" * 7
    if not original.endswith(padding):
        raise ValueError("expected seven 0x07 padding bytes")
    flag = original[:-len(padding)]
    if not (flag.startswith(b"sun{") and flag.endswith(b"}")):
        raise ValueError("recovered input does not match the expected flag format")

    print("transformed state:", state_bytes.hex())
    print("recovered block:  ", repr(original))
    print("flag:             ", flag.decode("ascii"))

if __name__ == "__main__":
    main()
