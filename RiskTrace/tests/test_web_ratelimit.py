import unittest

from web import ratelimit


class TestHit(unittest.TestCase):

    def setUp(self):
        ratelimit.reset()

    def test_allows_up_to_the_limit(self):
        for _ in range(3):
            self.assertTrue(ratelimit.hit("h", limit=3, window=60))

    def test_blocks_over_the_limit(self):
        for _ in range(3):
            ratelimit.hit("h", limit=3, window=60)
        self.assertFalse(ratelimit.hit("h", limit=3, window=60))

    def test_window_expiry_frees_the_slot(self):
        for _ in range(2):
            ratelimit.hit("h", now=0.0, limit=2, window=10)
        self.assertFalse(ratelimit.hit("h", now=1.0, limit=2, window=10))
        self.assertTrue(ratelimit.hit("h", now=11.0, limit=2, window=10))

    def test_keys_are_independent(self):
        ratelimit.hit("a", limit=1, window=60)
        self.assertTrue(ratelimit.hit("b", limit=1, window=60))

    def test_reset_clears_everything(self):
        ratelimit.hit("a", limit=1, window=60)
        ratelimit.reset()
        self.assertTrue(ratelimit.hit("a", limit=1, window=60))


if __name__ == "__main__":
    unittest.main()