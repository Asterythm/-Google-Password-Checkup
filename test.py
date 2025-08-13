import unittest
from typing import Set, Tuple
from ddh_psi_sum import Party1, Party2, run_protocol

class TestDDHPrivateIntersectionSum(unittest.TestCase):
    def setUp(self):
        """Set up common test data."""
        self.seed = b"test_seed_1234567890"  # Fixed seed for reproducibility

    def test_basic_intersection(self):
        """Test protocol with a simple intersection."""
        p1_identifiers = {"user1", "user2", "user3", "user4"}
        p2_pairs = {("user2", 10), ("user3", 20), ("user5", 30)}
        
        # Initialize parties with fixed seed
        p1 = Party1(p1_identifiers)
        p1.seed = self.seed
        p2 = Party2(p2_pairs)
        p2.seed = self.seed
        
        cardinality, intersection_sum = run_protocol(p1, p2)
        
        self.assertEqual(cardinality, 2, "Intersection cardinality should be 2")
        self.assertEqual(intersection_sum, 30, "Intersection sum should be 10 + 20 = 30")

    def test_empty_intersection(self):
        """Test protocol with no common identifiers."""
        p1_identifiers = {"user1", "user2"}
        p2_pairs = {("user3", 10), ("user4", 20)}
        
        p1 = Party1(p1_identifiers)
        p1.seed = self.seed
        p2 = Party2(p2_pairs)
        p2.seed = self.seed
        
        cardinality, intersection_sum = run_protocol(p1, p2)
        
        self.assertEqual(cardinality, 0, "Intersection cardinality should be 0")
        self.assertEqual(intersection_sum, 0, "Intersection sum should be 0")

    def test_single_intersection(self):
        """Test protocol with a single common identifier."""
        p1_identifiers = {"user1", "user2"}
        p2_pairs = {("user1", 15)}
        
        p1 = Party1(p1_identifiers)
        p1.seed = self.seed
        p2 = Party2(p2_pairs)
        p2.seed = self.seed
        
        cardinality, intersection_sum = run_protocol(p1, p2)
        
        self.assertEqual(cardinality, 1, "Intersection cardinality should be 1")
        self.assertEqual(intersection_sum, 15, "Intersection sum should be 15")

    def test_empty_input_p1(self):
        """Test protocol when P1 has no identifiers."""
        p1_identifiers: Set[str] = set()
        p2_pairs = {("user1", 10), ("user2", 20)}
        
        p1 = Party1(p1_identifiers)
        p1.seed = self.seed
        p2 = Party2(p2_pairs)
        p2.seed = self.seed
        
        cardinality, intersection_sum = run_protocol(p1, p2)
        
        self.assertEqual(cardinality, 0, "Intersection cardinality should be 0")
        self.assertEqual(intersection_sum, 0, "Intersection sum should be 0")

    def test_empty_input_p2(self):
        """Test protocol when P2 has no pairs."""
        p1_identifiers = {"user1", "user2"}
        p2_pairs: Set[Tuple[str, int]] = set()
        
        p1 = Party1(p1_identifiers)
        p1.seed = self.seed
        p2 = Party2(p2_pairs)
        p2.seed = self.seed
        
        cardinality, intersection_sum = run_protocol(p1, p2)
        
        self.assertEqual(cardinality, 0, "Intersection cardinality should be 0")
        self.assertEqual(intersection_sum, 0, "Intersection sum should be 0")

    def test_large_values(self):
        """Test protocol with larger intersection values."""
        p1_identifiers = {"user1", "user2", "user3"}
        p2_pairs = {("user1", 1000), ("user2", 2000), ("user3", 3000)}
        
        p1 = Party1(p1_identifiers)
        p1.seed = self.seed
        p2 = Party2(p2_pairs)
        p2.seed = self.seed
        
        cardinality, intersection_sum = run_protocol(p1, p2)
        
        self.assertEqual(cardinality, 3, "Intersection cardinality should be 3")
        self.assertEqual(intersection_sum, 6000, "Intersection sum should be 1000 + 2000 + 3000 = 6000")

    def test_hash_to_curve_consistency(self):
        """Test that hash_to_curve produces consistent results with same seed."""
        p1 = Party1({"user1"})
        p2 = Party2({("user1", 10)})
        p1.seed = self.seed
        p2.seed = self.seed
        
        point1 = p1.ddh.hash_to_curve("user1", self.seed)
        point2 = p2.ddh.hash_to_curve("user1", self.seed)
        
        self.assertEqual(point1.x, point2.x, "Hashed x-coordinates should match")
        self.assertEqual(point1.y, point2.y, "Hashed y-coordinates should match")

if __name__ == "__main__":
    unittest.main()