import unittest
import os
from src.core.logger import Logger

class TestLogger(unittest.TestCase):
    def setUp(self):
        self.log_file = "test_firewall.log"
        self.logger = Logger(self.log_file)

    def tearDown(self):
        if os.path.exists(self.log_file):
            os.remove(self.log_file)

    def test_log_info(self):
        self.logger.log("Test Info Message",level="INFO")
        with open(self.log_file, "r") as file:
            logs = file.read()
        self.assertIn("Test Info Message", logs)

    def test_log_error(self):
        self.logger.log("Test Error Message" , level="ERROR")
        with open(self.log_file, "r") as file:
            logs = file.read()
        self.assertIn("Test Error Message", logs)

if __name__ == "__main__":
    unittest.main()
