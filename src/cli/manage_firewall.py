import argparse
from src.cli.add_rule import add_rule_to_file
from src.cli.remove_rule import remove_rule_from_file
from src.cli.list_rules import list_all_rules

RULES_FILE = "default_rules.json"

def start_firewall():
    print("Firewall started.")

def track_connections():
    print("Tracking active connections.")

def monitor_traffic():
    print("Monitoring network traffic.")

def run_tests():
    print("Running unit tests...")

def add_rule(src, action):
    add_rule_to_file(RULES_FILE, {"src": src, "action": action})
    print(f"Added rule: Source={src}, Action={action}")

def remove_rule(src):
    remove_rule_from_file(RULES_FILE, src)
    print(f"Removed rule for Source={src}")

def list_rules():
    rules = list_all_rules(RULES_FILE)
    print("Current Firewall Rules:")
    for rule in rules:
        print(rule)

def main():
    parser = argparse.ArgumentParser(
        description="Python Firewall CLI",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    # Global options
    parser.add_argument("-s", "--start", action="store_true", help="Start the firewall")
    parser.add_argument("-c", "--track-connections", action="store_true", help="Track active connections")
    parser.add_argument("-m", "--monitor-traffic", action="store_true", help="Monitor network traffic")
    parser.add_argument("-u", "--run-tests", action="store_true", help="Run unit tests for the firewall")

    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Subcommands")

    # Add rule
    parser_add = subparsers.add_parser("add", help="Add a new rule")
    parser_add.add_argument("--src", required=True, help="Source IP address")
    parser_add.add_argument("--action", choices=["ALLOW", "BLOCK"], required=True, help="Action for the rule")

    # Remove rule
    parser_remove = subparsers.add_parser("remove", help="Remove an existing rule")
    parser_remove.add_argument("--src", required=True, help="Source IP address to remove the rule")

    # List rules
    parser_list = subparsers.add_parser("list", help="List all rules")

    # Parse arguments
    args = parser.parse_args()

    # Handle global options
    if args.start:
        start_firewall()
    elif args.track_connections:
        track_connections()
    elif args.monitor_traffic:
        monitor_traffic()
    elif args.run_tests:
        run_tests()
    elif args.command == "add":
        add_rule(args.src, args.action)
    elif args.command == "remove":
        remove_rule(args.src)
    elif args.command == "list":
        list_rules()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
