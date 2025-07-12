import argparse
from src.cli.add_rule import add_rule_to_file
from src.cli.remove_rule import remove_rule_from_file
from src.cli.list_rules import list_all_rules

RULES_FILE = "default_rules.json"

def add_rule(src, action):
    add_rule_to_file(RULES_FILE, {"src": src, "action": action})
    print(f"✅ Added rule: Source={src}, Action={action}")

def remove_rule(src):
    remove_rule_from_file(RULES_FILE, src)
    print(f"✅ Removed rule for Source={src}")

def list_rules():
    rules = list_all_rules(RULES_FILE)
    if not rules:
        print("🚫 No firewall rules found.")
    else:
        print("📋 Current Firewall Rules:")
        for rule in rules:
            print(f"🔸 {rule}")

def main():
    parser = argparse.ArgumentParser(
        description="Kavach Rule Manager CLI"
    )

    subparsers = parser.add_subparsers(dest="command", help="Rule management commands")

    # Add rule
    parser_add = subparsers.add_parser("add", help="Add a new rule")
    parser_add.add_argument("--src", required=True, help="Source IP address")
    parser_add.add_argument("--action", choices=["ALLOW", "BLOCK"], required=True, help="Action for the rule")

    # Remove rule
    parser_remove = subparsers.add_parser("remove", help="Remove an existing rule")
    parser_remove.add_argument("--src", required=True, help="Source IP address to remove the rule")

    # List rules
    subparsers.add_parser("list", help="List all current rules")

    args = parser.parse_args()

    if args.command == "add":
        add_rule(args.src, args.action)
    elif args.command == "remove":
        remove_rule(args.src)
    elif args.command == "list":
        list_rules()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
