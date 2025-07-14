import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
import main
import unittest
from test_cli import TestKavachCLI
from test_rules import TestRuleEngine
from test_logger import TestLogger
from test_filter import TestPacketFilter

def run_all_tests():
    print("Running CLI + Core tests...")
    suite = unittest.TestSuite()
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestKavachCLI))
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestRuleEngine))
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestLogger))
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestPacketFilter))
    unittest.TextTestRunner().run(suite)

if __name__ == "__main__":
    run_all_tests()
