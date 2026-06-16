import json
from generate_ex import build, verify, load_lab_rules
from main import get_node_console, GNS3_IP, lab_id_from_filename

FILE_TO_TEST = "vpn-template.json"

if __name__ == "__main__":
    with open("instanta_generata.json", "r") as f:
        result = json.load(f)

    lab_id    = lab_id_from_filename(FILE_TO_TEST)
    lab_rules = load_lab_rules(lab_id)
    context   = build(result, lab_rules)

    def console_fn(node_name):
        return get_node_console(node_name, lab_rules["project_id"])

    print("[VERIFY] Validating solution...")
    verify(context, lab_rules, console_fn, GNS3_IP)
    
    