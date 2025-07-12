import unittest
from src.tests.test_sniffer import TestPacketSniffer
from src.tests.test_rules import TestRuleEngine
from src.tests.test_filter import TestPacketFilter
from src.tests.test_logger import TestLogger


def run_all_tests():
    """
    Aggregates all tests and runs them together.
    """
    print("Running all unit tests...")
    # Create a test suite
    suite = unittest.TestSuite()

    # Add individual test cases or test classes to the suite
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestPacketSniffer))
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestRuleEngine))
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestPacketFilter))
    suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestLogger))

    # Run the test suite
    runner = unittest.TextTestRunner()
    runner.run(suite)


if __name__ == "__main__":
    run_all_tests()
