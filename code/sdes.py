"""S-DES（简化 DES）算法核心实现。

本模块严格采用作业说明中的变换盒。所有公开接口均使用仅含 0/1 的
字符串表示一个比特串，以避免字节序或编码差异影响交叉测试。
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable


P10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
P8 = (6, 3, 7, 4, 8, 5, 10, 9)
IP = (2, 6, 3, 1, 4, 8, 5, 7)
IP_INVERSE = (4, 1, 3, 5, 7, 2, 8, 6)
EP_BOX = (4, 1, 2, 3, 2, 3, 4, 1)
SP_BOX = (2, 4, 3, 1)

SBOX_1 = (
    (1, 0, 3, 2),
    (3, 2, 1, 0),
    (0, 2, 1, 3),
    (3, 1, 0, 2),
)
# 注意：此表按作业截图的备注，作为唯一标准实现。
SBOX_2 = (
    (0, 1, 2, 3),
    (2, 3, 1, 0),
    (3, 0, 1, 2),
    (2, 1, 0, 3),
)


def _validate_bits(bits: str, expected_length: int, name: str) -> str:
    """检查固定长度二进制输入，并返回去除首尾空白后的结果。"""
    normalized = bits.strip()
    if len(normalized) != expected_length or any(bit not in "01" for bit in normalized):
        raise ValueError(f"{name}必须是{expected_length}位二进制字符串（只含 0 或 1）。")
    return normalized


def _permute(bits: str, table: Iterable[int]) -> str:
    """按 1 起始的置换表重排比特。"""
    return "".join(bits[position - 1] for position in table)


def _xor(left: str, right: str) -> str:
    """对等长二进制字符串做异或。"""
    if len(left) != len(right):
        raise ValueError("异或的两个比特串长度必须相同。")
    return "".join("1" if a != b else "0" for a, b in zip(left, right))


def _left_shift_halves(bits: str, amount: int) -> str:
    """将 10 位密钥两半分别循环左移 amount 位。"""
    left, right = bits[:5], bits[5:]
    amount %= 5
    return left[amount:] + left[:amount] + right[amount:] + right[:amount]


def derive_subkeys(key: str) -> tuple[str, str]:
    """由 10 位主密钥生成 S-DES 的两个 8 位轮密钥 K1、K2。"""
    key = _validate_bits(key, 10, "密钥")
    p10_key = _permute(key, P10)
    shifted_once = _left_shift_halves(p10_key, 1)
    key_one = _permute(shifted_once, P8)
    shifted_twice = _left_shift_halves(shifted_once, 2)
    key_two = _permute(shifted_twice, P8)
    return key_one, key_two


def _substitute(four_bits: str, sbox: tuple[tuple[int, ...], ...]) -> str:
    """使用一个 S 盒把 4 位输入替换成 2 位输出。"""
    row = int(four_bits[0] + four_bits[3], 2)
    column = int(four_bits[1:3], 2)
    return format(sbox[row][column], "02b")


def round_function(right_half: str, subkey: str) -> str:
    """计算 F(R, K)：扩展置换、异或、S 盒与 SP 置换。"""
    right_half = _validate_bits(right_half, 4, "右半分组")
    subkey = _validate_bits(subkey, 8, "轮密钥")
    expanded = _permute(right_half, EP_BOX)
    mixed = _xor(expanded, subkey)
    substituted = _substitute(mixed[:4], SBOX_1) + _substitute(mixed[4:], SBOX_2)
    return _permute(substituted, SP_BOX)


def _fk(bits: str, subkey: str) -> str:
    """执行一次 Feistel 轮，但不交换左右半部。"""
    left, right = bits[:4], bits[4:]
    return _xor(left, round_function(right, subkey)) + right


def _switch(bits: str) -> str:
    """交换一个 8 位分组的左右 4 位。"""
    return bits[4:] + bits[:4]


def encrypt_block(plaintext: str, key: str) -> str:
    """用 10 位密钥加密一个 8 位明文分组，返回 8 位密文。"""
    plaintext = _validate_bits(plaintext, 8, "明文")
    key_one, key_two = derive_subkeys(key)
    state = _permute(plaintext, IP)
    state = _fk(state, key_one)
    state = _switch(state)
    state = _fk(state, key_two)
    return _permute(state, IP_INVERSE)


def decrypt_block(ciphertext: str, key: str) -> str:
    """用 10 位密钥解密一个 8 位密文分组，返回 8 位明文。"""
    ciphertext = _validate_bits(ciphertext, 8, "密文")
    key_one, key_two = derive_subkeys(key)
    state = _permute(ciphertext, IP)
    state = _fk(state, key_two)
    state = _switch(state)
    state = _fk(state, key_one)
    return _permute(state, IP_INVERSE)


def ascii_to_bits(text: str) -> list[str]:
    """将 ASCII 文本拆成 8 位分组；拒绝非 ASCII 字符以符合题意。"""
    try:
        raw = text.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("扩展模式仅接受 ASCII 字符（编码范围 0~127）。") from error
    return [format(byte, "08b") for byte in raw]


def bits_to_ascii(blocks: Iterable[str]) -> str:
    """将一组 8 位分组还原为 ASCII 文本。"""
    checked = [_validate_bits(block, 8, "密文分组") for block in blocks]
    try:
        return bytes(int(block, 2) for block in checked).decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("解密结果不是有效 ASCII 文本：请确认密钥和密文是否匹配。") from error


def parse_bit_blocks(text: str) -> list[str]:
    """读取以空格、换行或逗号分隔的 8 位二进制分组。"""
    normalized = text.replace(",", " ").split()
    if not normalized:
        raise ValueError("请输入至少一个 8 位二进制分组。")
    return [_validate_bits(block, 8, "输入分组") for block in normalized]


def encrypt_text(text: str, key: str) -> list[str]:
    """逐字节加密 ASCII 文本，返回二进制密文分组列表。"""
    return [encrypt_block(block, key) for block in ascii_to_bits(text)]


def decrypt_text(cipher_blocks: Iterable[str], key: str) -> str:
    """逐字节解密二进制密文分组，返回 ASCII 文本。"""
    return bits_to_ascii(decrypt_block(block, key) for block in cipher_blocks)


def bit_string(number: int, width: int) -> str:
    """将非负整数转换为固定长度的二进制文本。"""
    if not 0 <= number < (1 << width):
        raise ValueError(f"数字必须位于 0 到 {(1 << width) - 1} 之间。")
    return format(number, f"0{width}b")


def brute_force_keys(pairs: Iterable[tuple[str, str]]) -> list[str]:
    """枚举 1024 个密钥，找出能同时满足全部明密文对的候选密钥。"""
    checked_pairs = [
        (_validate_bits(plain, 8, "明文"), _validate_bits(cipher, 8, "密文"))
        for plain, cipher in pairs
    ]
    if not checked_pairs:
        raise ValueError("暴力破解至少需要一组明文—密文对。")
    matches: list[str] = []
    for candidate_number in range(1 << 10):
        candidate = bit_string(candidate_number, 10)
        if all(encrypt_block(plain, candidate) == cipher for plain, cipher in checked_pairs):
            matches.append(candidate)
    return matches


@dataclass(frozen=True)
class CollisionAnalysis:
    """固定明文下的密钥碰撞统计结果。"""

    plaintext: str
    distinct_ciphertexts: int
    collision_groups: int
    colliding_keys: int
    largest_group_size: int
    example_ciphertext: str | None
    example_keys: tuple[str, ...]


def analyze_collisions(plaintext: str) -> CollisionAnalysis:
    """统计所有 1024 个密钥对同一明文产生的密文碰撞。"""
    plaintext = _validate_bits(plaintext, 8, "明文")
    buckets: dict[str, list[str]] = defaultdict(list)
    for number in range(1 << 10):
        key = bit_string(number, 10)
        buckets[encrypt_block(plaintext, key)].append(key)
    groups = [keys for keys in buckets.values() if len(keys) > 1]
    example_ciphertext = next((cipher for cipher, keys in buckets.items() if len(keys) > 1), None)
    example_keys = tuple(buckets[example_ciphertext]) if example_ciphertext else ()
    return CollisionAnalysis(
        plaintext=plaintext,
        distinct_ciphertexts=len(buckets),
        collision_groups=len(groups),
        colliding_keys=sum(len(group) for group in groups),
        largest_group_size=max(map(len, buckets.values())),
        example_ciphertext=example_ciphertext,
        example_keys=example_keys,
    )
