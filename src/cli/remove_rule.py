import json

def remove_rule_from_file(rules_file, src_ip):
    try:
        with open(rules_file, "r") as file:
            rules = json.load(file)
    except FileNotFoundError:
        print("Rules file not found.")
        return

    updated_rules = [rule for rule in rules if rule.get("src") != src_ip]

    with open(rules_file, "w") as file:
        json.dump(updated_rules, file, indent=4)

    print(f"Removed rules with source IP: {src_ip}")
