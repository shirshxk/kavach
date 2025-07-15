import unittest
from unittest.mock import patch, MagicMock
import sys
import builtins
import importlib
import main

class TestKavachCLI(unittest.TestCase):
    def setUp(self):
        self.patcher_stdout = patch("builtins.print")
        self.mock_print = self.patcher_stdout.start()

    def tearDown(self):
        self.patcher_stdout.stop()

    def run_cli(self, args):
        with patch.object(sys, "argv", ["main.py"] + args):
            try:
                main.main()
            except SystemExit:
                pass  # Some argparse branches exit early

    @patch("main.initialize_firewall")
    def test_version(self, _):
        self.run_cli(["-i"])
        self.mock_print.assert_any_call('\x1b[36mKavach Firewall v1.0.0\x1b[0m')

    @patch("main.initialize_firewall")
    @patch("main.Helper.parse_rule_arg", return_value=("192.168.1.1", "BLOCK"))
    @patch("main.IpUtils.is_valid_ip", return_value=True)
    def test_add_ip_rule(self, *_):
        mock_pf = MagicMock()
        mock_logger = MagicMock()
        with patch("main.initialize_firewall", return_value=(mock_pf, mock_logger)):
            self.run_cli(["-a", "192.168.1.1,BLOCK"])
            mock_pf.rule_engine.add_rule.assert_called()

    @patch("main.initialize_firewall")
    @patch("main.Helper.parse_rule_arg", return_value=("192.168.1.1", "BLOCK"))
    @patch("main.IpUtils.is_valid_ip", return_value=True)
    def test_remove_ip_rule(self, *_):
        mock_pf = MagicMock()
        mock_pf.rule_engine.rules = [{"src": "192.168.1.1", "action": "BLOCK"}]
        mock_logger = MagicMock()
        with patch("main.initialize_firewall", return_value=(mock_pf, mock_logger)):
            self.run_cli(["-r", "192.168.1.1,BLOCK"])
            mock_pf.rule_engine.remove_rule.assert_called()

    @patch("main.initialize_firewall")
    def test_list_rules(self, _):
        mock_pf = MagicMock()
        mock_pf.rule_engine.rules = [{"src": "1.1.1.1", "action": "BLOCK"}]
        mock_logger = MagicMock()
        with patch("main.initialize_firewall", return_value=(mock_pf, mock_logger)):
            self.run_cli(["-l"])
            self.mock_print.assert_any_call("🔸 {'src': '1.1.1.1', 'action': 'BLOCK'}")

    @patch("main.get_traffic_statistics", return_value={"packets": 20, "data": 1200})
    @patch("main.Helper.detect_interface", return_value="eth0")
    def test_monitor_traffic(self, *_):
        self.run_cli(["-m", "1"])
        self.mock_print.assert_any_call('\x1b[32m✅ Monitoring Complete.\x1b[0m')


    def test_run_tests_invokes_runner(self):
        runner = importlib.import_module("src.tests.test_runner")
        self.assertTrue(hasattr(runner, "run_all_tests"))


    @patch("main.initialize_firewall")
    def test_reset_rules(self, _):
        mock_pf = MagicMock()
        mock_logger = MagicMock()
        with patch("main.initialize_firewall", return_value=(mock_pf, mock_logger)):
            self.run_cli(["-d"])
            mock_pf.rule_engine.save_rules.assert_called_once()
            self.mock_print.assert_any_call('\x1b[33m⚠️ All firewall rules cleared.\x1b[0m')

    @patch("main.Helper.parse_ports", return_value=[22])
    @patch("main.initialize_firewall")
    def test_block_ports(self, _init, _ports):
        mock_pf = MagicMock()
        mock_logger = MagicMock()
        with patch("main.initialize_firewall", return_value=(mock_pf, mock_logger)):
            self.run_cli(["-p", "22"])
            mock_pf.rule_engine.add_rule.assert_called_with({'port': 22, 'action': 'BLOCK'})

if __name__ == "__main__":
    unittest.main()
