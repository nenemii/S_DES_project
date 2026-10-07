"""输出可直接复制进作业报告的关键测试结果。运行：python demo_results.py"""

from __future__ import annotations

import time

from sdes import analyze_collisions, brute_force_keys, decrypt_block, encrypt_block, encrypt_text


def main() -> None:
    key = "1010000010"
    plaintext = "10101010"
    ciphertext = encrypt_block(plaintext, key)
    print("[第1关：基本测试]")
    print(f"P = {plaintext}, K = {key}")
    print(f"C = E(K, P) = {ciphertext}")
    print(f"D(K, C) = {decrypt_block(ciphertext, key)}")
    print()

    text = "This is a test"
    cipher_blocks = encrypt_text(text, key)
    print("[第3关：ASCII 扩展]")
    print(f"明文：{text}")
    print("二进制密文：" + " ".join(cipher_blocks))
    print()

    pairs = [(plaintext, ciphertext), ("01010101", encrypt_block("01010101", key))]
    start = time.perf_counter()
    candidates = brute_force_keys(pairs)
    elapsed = time.perf_counter() - start
    print("[第4关：暴力破解]")
    print("明密文对：" + "; ".join(f"{p} -> {c}" for p, c in pairs))
    print(f"候选密钥：{', '.join(candidates)}")
    print(f"枚举 1024 个密钥耗时：{elapsed:.6f} 秒")
    print()

    analysis = analyze_collisions(plaintext)
    print("[第5关：碰撞分析]")
    print(f"固定 P = {analysis.plaintext}")
    print(f"不同密文数：{analysis.distinct_ciphertexts}")
    print(f"发生碰撞的密文组数：{analysis.collision_groups}")
    print(f"最大碰撞组大小：{analysis.largest_group_size}")
    print(f"示例：C = {analysis.example_ciphertext} <- {', '.join(analysis.example_keys)}")


if __name__ == "__main__":
    main()
