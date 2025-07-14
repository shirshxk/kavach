import unittest
import os
from src.core.logger import Logger

class TestLogger(unittest.TestCase):
    def setUp(self):
        self.log_path = "logs/test_log.log"
        self.logger = Logger(log_file=self.log_path)

    def tearDown(self):
        if os.path.exists(self.log_path):
            os.remove(self.log_path)

    def test_log_info_message(self):
        msg = "Test info message"
        self.logger.log(msg, level="INFO")
        with open(self.log_path, "r") as file:
            logs = file.read()
        self.assertIn(msg, logs)

    def test_log_error_message(self):
        msg = "Test error message"
        self.logger.log(msg, level="ERROR")
        with open(self.log_path, "r") as file:
            logs = file.read()
        self.assertIn(msg, logs)

    def test_log_warning_message(self):
        msg = "Test warning message"
        self.logger.log(msg, level="WARNING")
        with open(self.log_path, "r") as file:
            logs = file.read()
        self.assertIn(msg, logs)

if __name__ == "__main__":
    unittest.main()
