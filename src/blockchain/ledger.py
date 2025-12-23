import time
import hashlib
import json
from core.merkle_tree import MerkleTree

class BlockchainModule:
    def __init__(self, difficulty=2):
        self.chain = []
        self.pending_transactions = []
        self.difficulty = difficulty
        self.create_genesis_block()

    def create_genesis_block(self):
        genesis_block = {
            'index': 0,
            'timestamp': time.time(),
            'transactions': ['GENESIS_BLOCK'],
            'merkle_root': '',
            'previous_hash': '0',
            'nonce': 0,
            'hash': ''
        }
        genesis_block['hash'] = self.calculate_hash(genesis_block)
        self.chain.append(genesis_block)

    def calculate_hash(self, block):
        block_string = json.dumps({
            'index': block['index'],
            'timestamp': block['timestamp'],
            'merkle_root': block['merkle_root'],
            'previous_hash': block['previous_hash'],
            'nonce': block['nonce']
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def add_transaction(self, transaction: str):
        self.pending_transactions.append(transaction)

    def mine_block(self):
        if not self.pending_transactions:
            return False

        tree = MerkleTree(self.pending_transactions)
        merkle_root = tree.get_root()

        last_block = self.chain[-1]
        new_block = {
            'index': len(self.chain),
            'timestamp': time.time(),
            'transactions': list(self.pending_transactions),
            'merkle_root': merkle_root,
            'previous_hash': last_block['hash'],
            'nonce': 0,
            'hash': ''
        }

        target = '0' * self.difficulty
        while True:
            new_hash = self.calculate_hash(new_block)
            if new_hash[:self.difficulty] == target:
                new_block['hash'] = new_hash
                break
            new_block['nonce'] += 1

        self.chain.append(new_block)
        self.pending_transactions = []
        return new_block

    def validate_chain(self) -> bool:
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i-1]

            if current['hash'] != self.calculate_hash(current):
                return False
            
            if current['previous_hash'] != previous['hash']:
                return False

            tree = MerkleTree(current['transactions'])
            if tree.get_root() != current['merkle_root']:
                return False

        return True
    
    def get_chain_dump(self):
        return json.dumps(self.chain, indent=4)