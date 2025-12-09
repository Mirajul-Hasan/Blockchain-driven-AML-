import hashlib
import json
from datetime import datetime
from uuid import uuid4
from typing import Optional, Dict, Any, List
import ecdsa

# ==========================
# Utilities
# ==========================

def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def now_iso() -> str:
    return datetime.utcnow().isoformat()


class Transaction:     # Blockchain
    def __init__(self,
                 tx_id: str,
                 timestamp: str,
                 sender_bank_id: str,
                 receiver_bank_id: str,
                 details_hash: str,
                 bank_signature_hex: Optional[str],
                 user_pubkey_hex: Optional[str]):
        self.tx_id = tx_id
        self.timestamp = timestamp
        self.sender_bank_id = sender_bank_id
        self.receiver_bank_id = receiver_bank_id
        self.details_hash = details_hash
        self.bank_signature_hex = bank_signature_hex
        self.user_pubkey_hex = user_pubkey_hex

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tx_id": self.tx_id,
            "timestamp": self.timestamp,
            "sender_bank_id": self.sender_bank_id,
            "receiver_bank_id": self.receiver_bank_id,
            "details_hash": self.details_hash,
            "bank_signature_hex": self.bank_signature_hex,
            "user_pubkey_hex": self.user_pubkey_hex,
        }


class Blockchain:
    def __init__(self, difficulty: int = 4):
        self.chain: List[Dict[str, Any]] = []
        self.pending_transactions: List[Transaction] = []
        self.difficulty = difficulty
        # genesis block
        self.new_block(proof=0, previous_hash="1")

    @staticmethod
    def hash_block(block: Dict[str, Any]) -> str:
        encoded = json.dumps(block, sort_keys=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @property
    def last_block(self) -> Dict[str, Any]:
        return self.chain[-1]

    def new_transaction(self, tx: Transaction) -> int:
        self.pending_transactions.append(tx)
        return self.last_block["index"] + 1

    def proof_of_work(self, index: int, previous_hash: str, tx_hashes: List[str]) -> int:
        nonce = 0
        prefix = "0" * self.difficulty
        while True:
            guess = f"{index}{previous_hash}{'|'.join(tx_hashes)}{nonce}"
            guess_hash = sha256_hex(guess)
            if guess_hash.startswith(prefix):
                return nonce
            nonce += 1

    def new_block(self, proof: int, previous_hash: Optional[str] = None) -> Dict[str, Any]:
        block_tx_dicts = [tx.to_dict() for tx in self.pending_transactions]
        block = {
            "index": len(self.chain) + 1,
            "timestamp": now_iso(),
            "tx_hashes": [tx["details_hash"] for tx in block_tx_dicts],
            "transactions": block_tx_dicts,
            "proof": proof,
            "previous_hash": previous_hash or self.hash_block(self.chain[-1]) if self.chain else "1",
        }
        self.pending_transactions = []
        self.chain.append(block)
        return block

    def mine_pending(self) -> Dict[str, Any]:
        previous_hash = self.hash_block(self.last_block)
        tx_hashes = [tx.details_hash for tx in self.pending_transactions]
        index = len(self.chain) + 1
        proof = self.proof_of_work(index=index, previous_hash=previous_hash, tx_hashes=tx_hashes)
        block = self.new_block(proof=proof, previous_hash=previous_hash)
        return block

    def is_chain_valid(self) -> bool:
        for i in range(1, len(self.chain)):
            prev = self.chain[i-1]
            cur = self.chain[i]
            if cur["previous_hash"] != self.hash_block(prev):
                return False
        return True


class CentralBankAuthority:   # Authorities and Actors
    def __init__(self, name: str):
        self.name = name


class Bank(CentralBankAuthority):
    """Local or foreign bank."""
    def __init__(self,
                 bank_id: str,
                 name: str,
                 location: str,
                 ownership: Optional[str] = None,
                 generate_keys: bool = True):
        super().__init__(name)
        self.bank_id = bank_id
        self.location = location
        self.ownership = ownership
        self.private_key = None
        self.public_key_hex = None
        if generate_keys:
            sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
            vk = sk.get_verifying_key()
            self.private_key = sk
            self.public_key_hex = vk.to_string().hex()

    def meta(self) -> Dict[str, Any]:
        data = {
            "bank_id": self.bank_id,
            "name": self.name,
            "location": self.location,
            "public_key": self.public_key_hex,
        }
        if self.ownership:
            data["ownership"] = self.ownership
        return data

    def sign(self, message_hex: str) -> Optional[str]:
        if not self.private_key:
            return None
        sig = self.private_key.sign(bytes.fromhex(message_hex))
        return sig.hex()


class CentralBank:
    def __init__(self, aml_threshold: float):
        self.aml_threshold = aml_threshold
        self.registered_hashes = set()
        self._sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        self.public_key_hex = self._sk.get_verifying_key().to_string().hex()

    def check_and_record_hash(self, details_hash: str) -> bool:
        if details_hash in self.registered_hashes:
            return True
        self.registered_hashes.add(details_hash)
        return True

    def decrypt_placeholder(self, _payload: str) -> bool:
        return True

    def aml_check(self, amount: float) -> bool:
        return amount <= self.aml_threshold


class FinanceMinistry:
    def __init__(self, policy_threshold: float):
        self.policy_threshold = policy_threshold

    def approve(self, amount: float, bank_signature_ok: bool) -> bool:
        return bank_signature_ok and amount <= self.policy_threshold


class DefenseIntelligence:
    def __init__(self, max_risk_amount: float):
        self.max_risk_amount = max_risk_amount
        self.watchlist = set()

    def approve(self, user_id: str, amount: float, bank_signature_ok: bool) -> bool:
        if user_id in self.watchlist:
            return False
        return bank_signature_ok and amount <= self.max_risk_amount


# ==========================
# Orchestrator
# ==========================
class CrossBorderSystem:
    def __init__(self, difficulty: int = 4):
        self.blockchain = Blockchain(difficulty=difficulty)
        self.banks: Dict[str, Bank] = {}
        self.central_bank: Optional[CentralBank] = None
        self.finance: Optional[FinanceMinistry] = None
        self.defense: Optional[DefenseIntelligence] = None

        # --- Predefined User Keypair ---
        self._user_sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        self.user_private_key_hex = self._user_sk.to_string().hex()
        self.user_public_key_hex = self._user_sk.get_verifying_key().to_string().hex()

        # --- Predefined Local Bank Keypair ---
        self._local_bank_sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        self.local_bank_private_key_hex = self._local_bank_sk.to_string().hex()
        self.local_bank_public_key_hex = self._local_bank_sk.get_verifying_key().to_string().hex()
        # NOTE: Local bank public key is NOT printed

    def register_bank(self, bank: Bank):
        self.banks[bank.bank_id] = bank

    def set_authorities(self, central_bank: CentralBank, finance: FinanceMinistry, defense: DefenseIntelligence):
        self.central_bank = central_bank
        self.finance = finance
        self.defense = defense

    @staticmethod
    def verify_bank_signature(bank_pub_hex: str, message_hex: str, signature_hex: Optional[str]) -> bool:
        if not bank_pub_hex or not signature_hex:
            return False
        try:
            vk = ecdsa.VerifyingKey.from_string(bytes.fromhex(bank_pub_hex), curve=ecdsa.SECP256k1)
            vk.verify(bytes.fromhex(signature_hex), bytes.fromhex(message_hex))
            return True
        except Exception:
            return False

    def process_transaction(self,
                            sender_bank_id: str,
                            receiver_bank_id: str,
                            user_name: str,
                            user_id: str,
                            amount: float) -> Optional[Dict[str, Any]]:
        if sender_bank_id not in self.banks:
            raise ValueError("Unknown sender bank")
        if receiver_bank_id not in self.banks:
            raise ValueError("Unknown receiver bank")
        if not (self.central_bank and self.finance and self.defense):
            raise RuntimeError("Authorities not configured")

        sender_bank = self.banks[sender_bank_id]
        receiver_bank = self.banks[receiver_bank_id]

        # --- User Cryptographic Identity ---
        print("\n--- User Cryptographic Identity ---")
        print(f"User Public Address: {self.user_public_key_hex}")

        # 1) Hash user data
        user_data_str = json.dumps({"user_name": user_name, "user_id": user_id, "amount": amount}, sort_keys=True)
        user_data_hash = sha256_hex(user_data_str)
        print(f"Hash of User Data: {user_data_hash}")

        # 2) User signs their data hash
        sig_bytes = self._user_sk.sign(bytes.fromhex(user_data_hash))
        user_signature_hex = sig_bytes.hex()
        print(f"User Digital Signature: {user_signature_hex}")

        # --- Local Bank Cryptographic Identity ---
        bank_data_obj = {
            "bank_id": sender_bank.bank_id,
            "name": sender_bank.name,
            "location": sender_bank.location,
            "ownership": sender_bank.ownership
        }
        bank_data_str = json.dumps(bank_data_obj, sort_keys=True)
        local_bank_hash = sha256_hex(bank_data_str)

        # Show Local Bank Hash
        print("\n--- Local Bank Cryptographic Identity ---")
        print(f"Local Bank Hash (from parameters): {local_bank_hash}")

        # Local bank signs its details hash
        local_bank_sig_bytes = self._local_bank_sk.sign(bytes.fromhex(local_bank_hash))
        local_bank_signature_hex = local_bank_sig_bytes.hex()

        # Authentication Phase
        combined_auth_data = json.dumps({"user_hash": user_data_hash, "bank_hash": local_bank_hash}, sort_keys=True)
        combined_auth_hash = sha256_hex(combined_auth_data)

        # Send to Central Bank
        self.central_bank.check_and_record_hash(combined_auth_hash)
        print("\n*** Hashes (Local Bank and User) are sent for Authentication. ***")

        # 3) Build details and hash for transaction
        details_obj = {
            "sender_bank": sender_bank.meta(),
            "receiver_bank": receiver_bank.meta(),
            "user": {"user_name": user_name, "user_id": user_id, "amount": amount, "user_public_key": self.user_public_key_hex},
        }
        details_str = json.dumps(details_obj, sort_keys=True)
        details_hash = sha256_hex(details_str)

        # 4) Bank signs the transaction hash
        bank_signature_hex = sender_bank.sign(details_hash)

        # 5) Central Bank checks
        cb_ok_hash = self.central_bank.check_and_record_hash(details_hash)
        cb_decrypt_ok = self.central_bank.decrypt_placeholder(details_hash)

        # 6) Verify bank signature
        bank_sig_ok = self.verify_bank_signature(sender_bank.public_key_hex, details_hash, bank_signature_hex)

        # 7) AML/Policy checks
        cb_aml_ok = self.central_bank.aml_check(amount)
        fin_ok = self.finance.approve(amount=amount, bank_signature_ok=bank_sig_ok)
        def_ok = self.defense.approve(user_id=user_id, amount=amount, bank_signature_ok=bank_sig_ok)

        consensus_met = all([cb_ok_hash, cb_decrypt_ok, bank_sig_ok, cb_aml_ok, fin_ok, def_ok])

        if not consensus_met:
            print("Consensus not met — transaction discarded.")
            return None

        # ✅ New line: print consensus success
        print("\nConsensus is met")

        # 8) Create transaction
        tx = Transaction(
            tx_id=str(uuid4()),
            timestamp=now_iso(),
            sender_bank_id=sender_bank_id,
            receiver_bank_id=receiver_bank_id,
            details_hash=details_hash,
            bank_signature_hex=bank_signature_hex,
            user_pubkey_hex=self.user_public_key_hex,
        )
        self.blockchain.new_transaction(tx)

        # 9) Mine block
        block = self.blockchain.mine_pending()
        block_hash = Blockchain.hash_block(block)

        # 10) Output
        print("\n=== Transaction Confirmed ===")
        print(f"Block Number: {block['index']}")
        print(f"Block Hash:   {block_hash}")
        print(f"Stored Tx Hashes: {block['tx_hashes']}")

        return {"block_index": block["index"], "block_hash": block_hash, "tx_hashes": block["tx_hashes"]}

# ==========================
# CLI
# ==========================
if __name__ == "__main__":
    system = CrossBorderSystem(difficulty=4)

    # Configure local bank
    local_bank_id = input("Enter Local Bank ID (e.g., BD001): ").strip()
    local_bank_name = input("Enter Local Bank Name: ").strip()
    local_bank_loc = input("Enter Local Bank Location (e.g., Dhaka, Bangladesh): ").strip()
    local_bank_owner = input("Enter Local Bank Ownership (public/private): ").strip()

    local_bank = Bank(bank_id=local_bank_id, name=local_bank_name, location=local_bank_loc,
                      ownership=local_bank_owner, generate_keys=True)

    # Configure foreign bank
    foreign_bank_id = input("Enter Foreign Bank ID (e.g., INT100): ").strip()
    foreign_bank_name = input("Enter Foreign Bank Name: ").strip()
    foreign_bank_loc = input("Enter Foreign Bank Location (e.g., London, UK): ").strip()

    foreign_bank = Bank(bank_id=foreign_bank_id, name=foreign_bank_name, location=foreign_bank_loc,
                        ownership=None, generate_keys=False)

    system.register_bank(local_bank)
    system.register_bank(foreign_bank)

    # Configure Authorities
    try:
        aml_threshold = float(input("Enter Central Bank AML threshold amount (e.g., 10000): ").strip())
        policy_threshold = float(input("Enter Finance Ministry policy threshold amount: ").strip())
        defense_threshold = float(input("Enter Defense/Intelligence max-risk amount: ").strip())

    except ValueError:
        print("Invalid numeric input for thresholds.")
        exit(1)

    cb = CentralBank(aml_threshold=aml_threshold)
    fin = FinanceMinistry(policy_threshold=policy_threshold)
    intel = DefenseIntelligence(max_risk_amount=defense_threshold)
    system.set_authorities(cb, fin, intel)

    # User inputs
    print("\n--- Enter User & Transaction Details ---")
    user_name = input("User Name: ").strip()
    user_id = input("User ID: ").strip()
    try:
        amount = float(input("Amount to transfer: ").strip())
    except ValueError:
        print("Invalid amount cannot be transferred.")
        exit(1)

    result = system.process_transaction(
        sender_bank_id=local_bank_id,
        receiver_bank_id=foreign_bank_id,
        user_name=user_name,
        user_id=user_id,
        amount=amount,
    )

    if result is None:
        print("Transaction failed.")
    else:
        print("Transaction succeeded (sent to foreign Bank) and recorded on-chain.")
