import json

def list_all_rules(rules_file):
    try:
        with open(rules_file, "r") as file:
            rules = json.load(file)
            if not rules:
                print("No rules found.")
                return

            print("Current Firewall Rules:")
            for rule in rules:
                print(f"Source: {rule.get('src')}, Action: {rule.get('action')}")
    except FileNotFoundError:
        print("Rules file not found.")
