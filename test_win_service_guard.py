import unittest
from win_service_guard import extract_binary_and_args, is_vulnerable, quote_path


class TestWinServiceGuard(unittest.TestCase):
    def test_extract_unquoted_binary(self):
        raw = r"C:\Program Files\Vendor\Service.exe -k netsvcs"
        binary, args = extract_binary_and_args(raw)
        self.assertEqual(binary, r"C:\Program Files\Vendor\Service.exe")
        self.assertEqual(args, "-k netsvcs")

    def test_extract_quoted_binary(self):
        raw = r'"C:\Program Files\Vendor\Service.exe" -k netsvcs'
        binary, args = extract_binary_and_args(raw)
        self.assertEqual(binary, r"C:\Program Files\Vendor\Service.exe")
        self.assertEqual(args, "-k netsvcs")

    def test_is_vulnerable(self):
        self.assertTrue(is_vulnerable(r"C:\Program Files\My App\service.exe"))
        self.assertFalse(is_vulnerable(r'"C:\Program Files\My App\service.exe"'))
        self.assertFalse(is_vulnerable(r"C:\Windows\System32\svchost.exe -k netsvcs"))

    def test_quote_path(self):
        raw = r"C:\Program Files\My App\service.exe --start"
        quoted = quote_path(raw)
        self.assertTrue(quoted.startswith(r'"C:\Program Files\My App\service.exe"'))
        self.assertTrue(quoted.endswith("--start"))


if __name__ == "__main__":
    unittest.main()
