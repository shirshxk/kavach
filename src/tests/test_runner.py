import unittest
from src.tests.test_cli import TestKavachCLI
from src.tests.test_rules import TestRuleEngine
from src.tests.test_logger import TestLogger
from src.tests.test_filter import TestPacketFilter

def run_all_tests():
    print("Running CLI + Core tests...")
    suite = unittest.TestSuite()
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestKavachCLI))
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestRuleEngine))
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestLogger))
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestPacketFilter))
    unittest.TextTestRunner().run(suite)