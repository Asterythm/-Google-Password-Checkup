import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from phe import paillier
import random
from typing import List, Tuple, Set

# Simulate the group G (prime256v1 curve) and hash function H
class DDHGroup:
    def __init__(self):
        self.curve = ec.SECP256R1()  # prime256v1 curve
        self.generator = ec.EllipticCurvePublicKey.from_encoded_point(
            self.curve, bytes.fromhex("04" + "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798" +
                                     "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
        ).public_numbers()

    def hash_to_curve(self, identifier: str, seed: bytes) -> ec.EllipticCurvePublicNumbers:
        """Hash identifier to a point on the elliptic curve using SHA-256 with a seed."""
        # Prepend seed to identifier to simulate new random oracle per execution
        data = seed + identifier.encode()
        for i in range(1000):  # Try up to 1000 times to find a valid point
            digest = hashes.Hash(hashes.SHA256())
            digest.update(data + i.to_bytes(4, 'big'))
            x = int.from_bytes(digest.finalize(), 'big') % self.curve.field_size
            try:
                # Try to create a point with this x-coordinate
                point = ec.EllipticCurvePublicNumbers(x, self.curve).to_key()
                return point
            except ValueError:
                continue
        raise ValueError("Failed to hash to curve")

    def exponentiate(self, point: ec.EllipticCurvePublicNumbers, exponent: int) -> ec.EllipticCurvePublicNumbers:
        """Exponentiate a point by a scalar."""
        key = ec.derive_private_key(exponent, self.curve)
        public_point = point.to_key()
        result = public_point.public_numbers()
        # Multiply point by scalar (exponent)
        for _ in range(exponent - 1):
            result = ec.EllipticCurvePublicNumbers(
                result.x + public_point.public_numbers().x,
                result.y + public_point.public_numbers().y,
                self.curve
            )
        return result

class Party:
    def __init__(self, name: str):
        self.name = name
        self.ddh = DDHGroup()
        self.key_pair = None
        self.other_public_key = None
        self.seed = os.urandom(16)  # Shared random seed for hash function
        self.k = random.randint(1, self.ddh.curve.field_size - 1)  # Private exponent

    def generate_paillier_keypair(self):
        """Generate Paillier keypair for additive homomorphic encryption."""
        self.key_pair = paillier.generate_paillier_keypair(n_length=1536)  # 768-bit primes as per paper

    def set_other_public_key(self, public_key: paillier.PaillierPublicKey):
        self.other_public_key = public_key

class Party1(Party):
    def __init__(self, identifiers: Set[str]):
        super().__init__("P1")
        self.identifiers = identifiers

    def round1(self) -> List[bytes]:
        """Round 1: Hash and exponentiate identifiers, send to P2."""
        hashed = [self.ddh.hash_to_curve(v, self.seed) for v in self.identifiers]
        exponentiated = [self.ddh.exponentiate(h, self.k) for h in hashed]
        # Serialize points for transmission (shuffled)
        result = [e.to_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint) for e in exponentiated]
        random.shuffle(result)
        return result

    def round3(self, z: List[bytes], w_pairs: List[Tuple[bytes, int]]) -> Tuple[int, int]:
        """Round 3: Compute intersection and homomorphic sum."""
        # Deserialize Z
        z_points = set()
        for z_bytes in z:
            point = ec.EllipticCurvePublicKey.from_encoded_point(self.ddh.curve, z_bytes).public_numbers()
            z_points.add((point.x, point.y))

        # Process P2's pairs
        intersection = []
        for w_bytes, enc_t in w_pairs:
            w_point = ec.EllipticCurvePublicKey.from_encoded_point(self.ddh.curve, w_bytes).public_numbers()
            w_exp = self.ddh.exponentiate(w_point, self.k)
            if (w_exp.x, w_exp.y) in z_points:
                intersection.append(enc_t)

        # Compute cardinality and sum
        cardinality = len(intersection)
        if cardinality == 0:
            sum_ciphertext = self.other_public_key.encrypt(0)
        else:
            sum_ciphertext = intersection[0]
            for enc_t in intersection[1:]:
                sum_ciphertext = sum_ciphertext + enc_t  # Homomorphic addition
            # Randomize ciphertext (ARefresh)
            sum_ciphertext = sum_ciphertext + self.other_public_key.encrypt(0)
        return cardinality, sum_ciphertext

class Party2(Party):
    def __init__(self, pairs: Set[Tuple[str, int]]):
        super().__init__("P2")
        self.pairs = pairs
        self.generate_paillier_keypair()

    def round2(self, v_hashed: List[bytes]) -> Tuple[List[bytes], List[Tuple[bytes, int]]]:
        """Round 2: Exponentiate received points, process own pairs."""
        # Deserialize and exponentiate received points
        z = []
        for v_bytes in v_hashed:
            point = ec.EllipticCurvePublicKey.from_encoded_point(self.ddh.curve, v_bytes).public_numbers()
            z_point = self.ddh.exponentiate(point, self.k)
            z.append(z_point.to_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint))
        random.shuffle(z)

        # Process own pairs
        w_pairs = []
        for w, t in self.pairs:
            w_hash = self.ddh.hash_to_curve(w, self.seed)
            w_exp = self.ddh.exponentiate(w_hash, self.k)
            enc_t = self.key_pair.public_key.encrypt(t)
            w_bytes = w_exp.to_key().public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
            w_pairs.append((w_bytes, enc_t))
        random.shuffle(w_pairs)
        return z, w_pairs

    def output(self, sum_ciphertext: int) -> int:
        """Decrypt the sum ciphertext to get the intersection sum."""
        return self.key_pair.decrypt(sum_ciphertext)

def run_protocol(p1: Party1, p2: Party2) -> Tuple[int, int]:
    """Execute the DDH-based Private Intersection-Sum protocol."""
    # Setup: P2 sends public key to P1
    p1.set_other_public_key(p2.key_pair.public_key)

    # Round 1
    v_hashed = p1.round1()

    # Round 2
    z, w_pairs = p2.round2(v_hashed)

    # Round 3
    cardinality, sum_ciphertext = p1.round3(z, w_pairs)

    # Output
    intersection_sum = p2.output(sum_ciphertext)
    return cardinality, intersection_sum

# Example usage
if __name__ == "__main__":
    # Sample inputs
    p1_identifiers = {"user1", "user2", "user3", "user4"}
    p2_pairs = {("user2", 10), ("user3", 20), ("user5", 30)}
    
    # Initialize parties
    p1 = Party1(p1_identifiers)
    p2 = Party2(p2_pairs)
    
    # Run protocol
    cardinality, intersection_sum = run_protocol(p1, p2)
    print(f"Intersection Cardinality: {cardinality}")
    print(f"Intersection Sum: {intersection_sum}")