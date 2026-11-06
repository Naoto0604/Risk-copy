import os
import unittest
from unittest import mock

from web import auth


class TestPassword(unittest.TestCase):

    def tearDown(self):
        auth.reset(None)

    def test_env_value_is_used(self):
        with mock.patch.dict(os.environ, {"RISKTRACE_PASSWORD": "from-env"}):
            auth.reset(None)
            self.assertEqual(auth.password(), "from-env")

    def test_value_is_generated_when_absent(self):
        with mock.patch.dict(os.environ, {"RISKTRACE_PASSWORD": ""}):
            auth.reset(None)
            self.assertGreaterEqual(len(auth.password()), auth.MIN_LENGTH)

    def test_generated_value_is_stable(self):
        with mock.patch.dict(os.environ, {"RISKTRACE_PASSWORD": ""}):
            auth.reset(None)
            self.assertEqual(auth.password(), auth.password())

    def test_check_accepts_matching(self):
        auth.reset("abc12345")
        self.assertTrue(auth.check("abc12345"))

    def test_check_rejects_wrong(self):
        auth.reset("abc12345")
        self.assertFalse(auth.check("nope"))

    def test_check_rejects_empty(self):
        auth.reset("abc12345")
        self.assertFalse(auth.check(""))
        self.assertFalse(auth.check(None))


if __name__ == "__main__":
    unittest.main()