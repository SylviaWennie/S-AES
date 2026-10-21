"""简化 AES (S-AES) 教学实现：核心算法、五关扩展、图解数据和本地实验台。"""

from .core import SPEC_ID, decrypt_block, encrypt_block, expand_key, round_keys

__all__ = ["SPEC_ID", "decrypt_block", "encrypt_block", "expand_key", "round_keys"]
