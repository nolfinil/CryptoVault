import hashlib
from typing import List, Optional

class MerkleTree:
    def __init__(self, data_list: List[str] = None):
        self.leaves = []
        self.levels = []
        if data_list:
            self.build_tree(data_list)

    def _hash(self, data: str) -> str:
        return hashlib.sha256(data.encode('utf-8')).hexdigest()

    def build_tree(self, data_list: List[str]) -> str:
        if not data_list:
            self.levels = []
            return None

        self.leaves = [self._hash(data) for data in data_list]
        current_level = self.leaves
        self.levels = [current_level]

        while len(current_level) > 1:
            next_level = []
            if len(current_level) % 2 != 0:
                current_level.append(current_level[-1])

            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i+1]
                combined_hash = self._hash(left + right)
                next_level.append(combined_hash)
            
            current_level = next_level
            self.levels.append(current_level)

        return self.levels[-1][0]

    def get_root(self) -> Optional[str]:
        if not self.levels:
            return None
        return self.levels[-1][0]

    def get_proof(self, index: int) -> List[dict]:
        if not self.levels or index >= len(self.leaves):
            return []

        proof = []
        for level in self.levels[:-1]:
            is_right_node = index % 2 == 1
            sibling_index = index - 1 if is_right_node else index + 1

            if sibling_index < len(level):
                sibling_hash = level[sibling_index]
                direction = 'left' if is_right_node else 'right'
                proof.append({'hash': sibling_hash, 'direction': direction})
            
            index //= 2

        return proof

    def verify_proof(self, data: str, proof: List[dict], root: str) -> bool:
        current_hash = self._hash(data)
        
        for node in proof:
            if node['direction'] == 'left':
                current_hash = self._hash(node['hash'] + current_hash)
            else:
                current_hash = self._hash(current_hash + node['hash'])
                
        return current_hash == root