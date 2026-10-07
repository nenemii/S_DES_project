"""S-DES 作业图形界面入口。运行：python app.py"""

from __future__ import annotations

import time
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

from sdes import (
    analyze_collisions,
    brute_force_keys,
    decrypt_block,
    decrypt_text,
    derive_subkeys,
    encrypt_block,
    encrypt_text,
    parse_bit_blocks,
)


class SdesApplication(tk.Tk):
    """提供基本、ASCII 扩展、暴力破解和碰撞分析的交互式窗口。"""

    def __init__(self) -> None:
        super().__init__()
        self.title("S-DES 算法实现与测试")
        self.geometry("1040x720")
        self.minsize(900, 620)
        self._configure_styles()
        self._build_interface()

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TFrame", background="#F4F7FB")
        style.configure("TLabel", background="#F4F7FB", foreground="#17233A", font=("Microsoft YaHei UI", 10))
        style.configure("Title.TLabel", font=("Microsoft YaHei UI", 22, "bold"), foreground="#17233A")
        style.configure("Subtitle.TLabel", font=("Microsoft YaHei UI", 10), foreground="#62718A")
        style.configure("Hint.TLabel", foreground="#62718A", font=("Microsoft YaHei UI", 9))
        style.configure("Result.TLabel", font=("Consolas", 16, "bold"), foreground="#2563EB")
        style.configure("Metric.TLabel", font=("Consolas", 10, "bold"), foreground="#0F766E")
        style.configure(
            "TButton",
            padding=(14, 8),
            font=("Microsoft YaHei UI", 10, "bold"),
            foreground="#FFFFFF",
            background="#2563EB",
            borderwidth=0,
        )
        style.map("TButton", background=[("active", "#1D4ED8"), ("disabled", "#A9BCE5")])
        style.configure(
            "Secondary.TButton",
            foreground="#27466F",
            background="#EAF2FF",
            borderwidth=0,
        )
        style.map("Secondary.TButton", background=[("active", "#D6E7FF")])
        style.configure(
            "Card.TLabelframe",
            background="#FFFFFF",
            bordercolor="#D9E2F0",
            lightcolor="#D9E2F0",
            darkcolor="#D9E2F0",
            relief="solid",
        )
        style.configure(
            "Card.TLabelframe.Label",
            background="#FFFFFF",
            foreground="#17233A",
            font=("Microsoft YaHei UI", 11, "bold"),
        )
        style.configure("TEntry", fieldbackground="#FFFFFF", foreground="#17233A", padding=(9, 7))
        style.configure("TNotebook", background="#F4F7FB", borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            background="#E9EEF7",
            foreground="#52627C",
            font=("Microsoft YaHei UI", 10, "bold"),
            padding=(18, 10),
            borderwidth=0,
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", "#FFFFFF"), ("active", "#DDE9FC")],
            foreground=[("selected", "#2563EB")],
        )

    def _build_interface(self) -> None:
        hero = tk.Frame(self, bg="#12213E", height=126)
        hero.pack(fill="x")
        hero.pack_propagate(False)
        hero_content = tk.Frame(hero, bg="#12213E")
        hero_content.pack(fill="both", expand=True, padx=30, pady=20)
        tk.Label(
            hero_content,
            text="S-DES LAB",
            font=("Segoe UI", 9, "bold"),
            fg="#93C5FD",
            bg="#12213E",
        ).pack(anchor="w")
        tk.Label(
            hero_content,
            text="S-DES 算法实现与安全分析",
            font=("Microsoft YaHei UI", 23, "bold"),
            fg="#FFFFFF",
            bg="#12213E",
        ).pack(anchor="w", pady=(2, 0))
        tk.Label(
            hero_content,
            text="8 位分组 · 10 位密钥 · 两轮 Feistel 结构 · 支持加解密、分析与实验验证",
            font=("Microsoft YaHei UI", 10),
            fg="#BED0EB",
            bg="#12213E",
        ).pack(anchor="w", pady=(2, 0))

        container = ttk.Frame(self, padding=(24, 20, 24, 22))
        container.pack(fill="both", expand=True)
        ttk.Label(
            container,
            text="选择实验模块，输入数据后即可得到可复制、可用于交叉测试的标准结果。",
            style="Subtitle.TLabel",
        ).pack(anchor="w", pady=(0, 12))

        notebook = ttk.Notebook(container)
        notebook.pack(fill="both", expand=True)
        self._build_basic_tab(notebook)
        self._build_text_tab(notebook)
        self._build_crack_tab(notebook)
        self._build_collision_tab(notebook)

    @staticmethod
    def _entry(parent: ttk.Frame, row: int, label: str, default: str, width: int = 48) -> ttk.Entry:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=(0, 10), pady=8)
        entry = ttk.Entry(parent, width=width)
        entry.grid(row=row, column=1, sticky="ew", pady=8)
        entry.insert(0, default)
        return entry

    def _build_basic_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=20)
        notebook.add(tab, text="第 1 关：基本测试")
        tab.columnconfigure(1, weight=1)
        self.basic_input = self._entry(tab, 0, "8 位输入（明文或密文）", "10101010")
        self.basic_key = self._entry(tab, 1, "10 位密钥", "1010000010")
        buttons = ttk.Frame(tab)
        buttons.grid(row=2, column=1, sticky="w", pady=10)
        ttk.Button(buttons, text="加密分组  →", command=lambda: self._process_basic(True)).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="←  解密分组", style="Secondary.TButton", command=lambda: self._process_basic(False)).pack(side="left")
        self.basic_result = ttk.Label(tab, text="结果会显示在这里", style="Result.TLabel")
        self.basic_result.grid(row=3, column=1, sticky="w", pady=(12, 10))
        self.basic_detail = ttk.Label(tab, text="", style="Hint.TLabel")
        self.basic_detail.grid(row=4, column=1, sticky="w")
        ttk.Label(
            tab,
            text="提示：输入必须严格为 0/1。加密和解密采用 K1/K2 相反的轮次顺序。",
            style="Hint.TLabel",
        ).grid(row=5, column=1, sticky="w", pady=(22, 0))

    def _process_basic(self, encrypt: bool) -> None:
        try:
            value = self.basic_input.get()
            key = self.basic_key.get()
            result = encrypt_block(value, key) if encrypt else decrypt_block(value, key)
            key_one, key_two = derive_subkeys(key)
            action = "密文" if encrypt else "明文"
            self.basic_result.config(text=f"{action}：{result}")
            self.basic_detail.config(text=f"本次派生轮密钥：K1 = {key_one}，K2 = {key_two}")
        except ValueError as error:
            self._show_error(error)

    def _build_text_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=20)
        notebook.add(tab, text="第 3 关：ASCII 扩展")
        tab.columnconfigure(0, weight=1)
        ttk.Label(tab, text="10 位密钥").grid(row=0, column=0, sticky="w")
        self.text_key = ttk.Entry(tab, width=48)
        self.text_key.grid(row=1, column=0, sticky="ew", pady=(3, 12))
        self.text_key.insert(0, "1010000010")
        ttk.Label(tab, text="ASCII 明文（加密时填写）").grid(row=2, column=0, sticky="w")
        self.plain_text = scrolledtext.ScrolledText(tab, height=5, wrap="word", font=("Consolas", 10))
        self.plain_text.grid(row=3, column=0, sticky="nsew", pady=(3, 10))
        self.plain_text.insert("1.0", "This is a test")
        ttk.Label(tab, text="二进制密文（每组 8 位，可用空格/换行/逗号分隔）").grid(row=4, column=0, sticky="w")
        self.cipher_text = scrolledtext.ScrolledText(tab, height=6, wrap="word", font=("Consolas", 10))
        self.cipher_text.grid(row=5, column=0, sticky="nsew", pady=(3, 10))
        buttons = ttk.Frame(tab)
        buttons.grid(row=6, column=0, sticky="w", pady=4)
        ttk.Button(buttons, text="ASCII 加密  →", command=self._encrypt_text).pack(side="left", padx=(0, 8))
        ttk.Button(buttons, text="←  二进制解密", style="Secondary.TButton", command=self._decrypt_text).pack(side="left")
        ttk.Label(tab, text="为保证可交叉测试，密文按完整 8 位二进制分组显示。", style="Hint.TLabel").grid(
            row=7, column=0, sticky="w", pady=(12, 0)
        )
        tab.rowconfigure(3, weight=1)
        tab.rowconfigure(5, weight=1)

    def _encrypt_text(self) -> None:
        try:
            cipher_blocks = encrypt_text(self.plain_text.get("1.0", "end-1c"), self.text_key.get())
            self.cipher_text.delete("1.0", "end")
            self.cipher_text.insert("1.0", " ".join(cipher_blocks))
        except ValueError as error:
            self._show_error(error)

    def _decrypt_text(self) -> None:
        try:
            blocks = parse_bit_blocks(self.cipher_text.get("1.0", "end-1c"))
            plaintext = decrypt_text(blocks, self.text_key.get())
            self.plain_text.delete("1.0", "end")
            self.plain_text.insert("1.0", plaintext)
        except ValueError as error:
            self._show_error(error)

    def _build_crack_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=20)
        notebook.add(tab, text="第 4 关：暴力破解")
        tab.columnconfigure(0, weight=1)
        ttk.Label(tab, text="明文—密文对（每行一组：8 位明文 空格 8 位密文；可提供多组）").grid(row=0, column=0, sticky="w")
        self.pair_text = scrolledtext.ScrolledText(tab, height=8, font=("Consolas", 10))
        self.pair_text.grid(row=1, column=0, sticky="nsew", pady=(5, 10))
        self.pair_text.insert("1.0", "10101010 10001101\n01010101 11000001")
        ttk.Button(tab, text="开始遍历 1024 个密钥", command=self._crack_keys).grid(row=2, column=0, sticky="w")
        self.crack_result = scrolledtext.ScrolledText(tab, height=8, state="disabled", font=("Consolas", 10))
        self.crack_result.grid(row=3, column=0, sticky="nsew", pady=(12, 0))
        tab.rowconfigure(1, weight=1)
        tab.rowconfigure(3, weight=1)

    def _crack_keys(self) -> None:
        try:
            pairs = []
            for line_number, line in enumerate(self.pair_text.get("1.0", "end-1c").splitlines(), start=1):
                if not line.strip():
                    continue
                pieces = line.replace(",", " ").split()
                if len(pieces) != 2:
                    raise ValueError(f"第 {line_number} 行需要恰好包含明文和密文两个分组。")
                pairs.append((pieces[0], pieces[1]))
            start = time.perf_counter()
            matches = brute_force_keys(pairs)
            elapsed = time.perf_counter() - start
            text = f"耗时：{elapsed:.4f} 秒\n候选密钥数：{len(matches)}\n"
            text += "候选密钥：" + ("、".join(matches) if matches else "无（请检查输入）")
            self._set_output(self.crack_result, text)
        except ValueError as error:
            self._show_error(error)

    def _build_collision_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook, padding=20)
        notebook.add(tab, text="第 5 关：碰撞分析")
        tab.columnconfigure(0, weight=1)
        ttk.Label(tab, text="任意 8 位明文分组").grid(row=0, column=0, sticky="w")
        self.collision_plaintext = ttk.Entry(tab, width=48)
        self.collision_plaintext.grid(row=1, column=0, sticky="w", pady=(3, 12))
        self.collision_plaintext.insert(0, "10101010")
        ttk.Button(tab, text="开始分析 1024 个密钥", command=self._analyze_collisions).grid(row=2, column=0, sticky="w")
        self.collision_result = scrolledtext.ScrolledText(tab, height=12, state="disabled", font=("Consolas", 10))
        self.collision_result.grid(row=3, column=0, sticky="nsew", pady=(12, 0))
        tab.rowconfigure(3, weight=1)

    def _analyze_collisions(self) -> None:
        try:
            analysis = analyze_collisions(self.collision_plaintext.get())
            example = "、".join(analysis.example_keys)
            text = (
                f"固定明文 P = {analysis.plaintext}\n"
                f"1024 个密钥产生的不同密文数：{analysis.distinct_ciphertexts}\n"
                f"发生碰撞的密文分组数：{analysis.collision_groups}\n"
                f"参与碰撞的密钥数：{analysis.colliding_keys}\n"
                f"单个密文对应的最大密钥数量：{analysis.largest_group_size}\n\n"
                f"示例：密文 C = {analysis.example_ciphertext}\n"
                f"可由不同密钥加密得到：{example}\n\n"
                "结论：S-DES 的密钥空间为 1024，而一个分组的密文空间只有 256；"
                "对固定 P，按抽屉原理必然存在 Ki ≠ Kj 使 E(Ki, P) = E(Kj, P)。"
            )
            self._set_output(self.collision_result, text)
        except ValueError as error:
            self._show_error(error)

    @staticmethod
    def _set_output(widget: scrolledtext.ScrolledText, text: str) -> None:
        widget.config(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.config(state="disabled")

    def _show_error(self, error: Exception) -> None:
        messagebox.showerror("输入有误", str(error), parent=self)


if __name__ == "__main__":
    SdesApplication().mainloop()
