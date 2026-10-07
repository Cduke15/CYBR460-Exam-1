import hmac # Standard library constant-time tool
from Cryptodome.Hash import HMAC, SHA256

class ReplayProtectedReceiver:
    def __init__(self, mac_key: bytes):
        self.mac_key = mac_key
        self.senders = {} # Tracks highest sequence per sender_id

    def accept(self, sender_id: str, sequence: int, message: bytes, tag: bytes) -> bool:
        # Recompute the tag over sender_id, sequence, and message
        engine = HMAC.new(self.mac_key, digestmod=SHA256)
        engine.update(sender_id.encode() + str(sequence).encode() + message)
        
        # Verify tag and track freshness
        if not hmac.compare_digest(tag, engine.digest()):
            return False
            
        if sequence <= self.senders.get(sender_id, -1):
            return False

        self.senders[sender_id] = sequence
        return True

        # Test setup
if __name__ == "__main__":
    k = b"A" * 32
    rx = ReplayProtectedReceiver(k)
    
    # Helper to sign a quick mock message
    def sign(sid, seq, msg):
        e = HMAC.new(k, digestmod=SHA256)
        e.update(sid.encode() + str(seq).encode() + msg)
        return e.digest()

    good_tag = sign("alice", 5, b"pay $10")

    # Runs the four scenarios
    print("1. Valid msg:", rx.accept("alice", 5, b"pay $10", good_tag))
    print("2. Tampered :", rx.accept("alice", 6, b"pay $99", good_tag))
    print("3. Replay   :", rx.accept("alice", 5, b"pay $10", good_tag))
    print("4. Out-order:", rx.accept("alice", 3, b"old text", sign("alice", 3, b"old text")))

