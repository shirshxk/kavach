import json

def add_rule_to_file(rules_file, rule):
    try:
        with open(rules_file, "r") as file:
            rules = json.load(file)
    except FileNotFoundError:
        rules = []

    rules.append(rule)

    with open(rules_file, "w") as file:
        json.dump(rules, file, indent=4)

    print(f"Rule added: {rule}")
