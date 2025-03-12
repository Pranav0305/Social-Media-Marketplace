import hashlib
import time

class SimpleBlockchain:
    def __init__(self):
        self.chain = []
        self.create_block(message="Genesis Block", sender="System", recipient="All", previous_hash="0")

    def create_block(self, message, sender, recipient, previous_hash):
        message_hash = hashlib.sha256(message.encode()).hexdigest()
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'sender': sender,
            'recipient': recipient,
            'message_hash': message_hash,
            'previous_hash': previous_hash
        }
        self.chain.append(block)
        return block

    def add_message(self, message, sender, recipient):
        previous_hash = self.chain[-1]['message_hash']
        return self.create_block(message, sender, recipient, previous_hash)

    def get_chain(self):
        return self.chain
