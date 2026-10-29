import unittest
from win_service_guard import quote_path

class TestGuard(unittest.TestCase):
    def test_quote_path_simple(self):
        p = r"C:\Program Files\My App\service.exe"
        res = quote_path(p)
        self.assertTrue(res.startswith('"'))
        self.assertTrue(res.endswith('"'))

if __name__ == r"__main__":
    unittest.main()
