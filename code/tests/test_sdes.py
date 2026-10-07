"""S-DES 核心算法的自动化测试。运行：python -m unittest discover -s tests -v"""

import unittest

from sdes import (
    analyze_collisions,
    brute_force_keys,
    decrypt_block,
    decrypt_text,
    derive_subkeys,
    encrypt_block,
    encrypt_text,
)


class SdesTests(unittest.TestCase):
    def test_key_expansion(self) -> None:
        self.assertEqual(derive_subkeys("1010000010"), ("10100100", "01000011"))

    def test_known_vector(self) -> None:
        # 该向量按本作业的 SBox2 表得到，便于跨程序对照。
        self.assertEqual(encrypt_block("10101010", "1010000010"), "10001101")
        self.assertEqual(decrypt_block("10001101", "1010000010"), "10101010")

    def test_all_blocks_round_trip(self) -> None:
        key = "1010000010"
        for number in range(256):
            plaintext = format(number, "08b")
            self.assertEqual(decrypt_block(encrypt_block(plaintext, key), key), plaintext)

    def test_ascii_extension_round_trip(self) -> None:
        text = "This is a test!"
        key = "1010000010"
        ciphertext = encrypt_text(text, key)
        self.assertEqual(decrypt_text(ciphertext, key), text)

    def test_brute_force_finds_actual_key(self) -> None:
        key = "1010000010"
        pairs = [("10101010", encrypt_block("10101010", key)), ("01010101", encrypt_block("01010101", key))]
        self.assertIn(key, brute_force_keys(pairs))

    def test_collision_is_unavoidable_for_fixed_plaintext(self) -> None:
        analysis = analyze_collisions("10101010")
        self.assertLessEqual(analysis.distinct_ciphertexts, 256)
        self.assertGreater(analysis.collision_groups, 0)
        self.assertGreaterEqual(len(analysis.example_keys), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
