import ipaddress
import json
import os
import re
import telnetlib
import time


def load_lab_rules(lab_id: str) -> dict:
    path = os.path.join("labs", f"{lab_id}.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


#  BUILD 

def _derive(rule: dict, context: dict) -> str:
    t = rule["type"]

    if t == "static":
        return rule["value"]

    if t in ("network_address", "netmask"):
        gw      = context[rule["from"]]
        prefix  = str(rule["prefix"])
        network = ipaddress.IPv4Interface(f"{gw}/{prefix}").network
        return str(network.network_address) if t == "network_address" else str(network.netmask)

    if t == "vlan_from_ip":
        gw       = context[rule["from"]]
        octet    = int(gw.split(".")[rule["octet"]])
        fallback = rule["fallback"]
        vlan_id  = octet
        if vlan_id in (0, 1):
            vlan_id = fallback
        return str(vlan_id)

    if t == "ip_offset":
        gw   = context[rule["from"]]
        base = gw.rsplit(".", 1)[0]
        return f"{base}.{rule['offset']}"


    if t == "slugify":
        return re.sub(r"\s+", "_", context[rule["from"]])

    raise ValueError(f"Unknown type: {t}")


def build(scenario: dict, lab_rules: dict) -> dict:
    rules   = scenario["generation_rules"]
    context = {}

    for key in lab_rules["build"]["from_llm"]:
        context[key] = str(rules[key])

    for rule in lab_rules["build"]["derived"]:
        context[rule["key"]] = _derive(rule, context)

    return context


#  VERIFY 

def _resolve(text: str, context: dict) -> str:
    for key, value in context.items():
        text = text.replace(f"{{{{{key}}}}}", value)
    return text


def _run_command(gns3_ip: str, port: int, command: str) -> str:
    tn = telnetlib.Telnet(gns3_ip, port, 15)
    time.sleep(1)
    tn.write(b"\r\n")
    time.sleep(0.5)
    tn.write(b"\x03")
    time.sleep(0.5)
    tn.write(b"enable\r\n")
    time.sleep(0.5)
    tn.write(command.encode("ascii") + b"\r\n")
    output = tn.read_very_eager().decode("utf-8", errors="ignore")
    time.sleep(2)
    output += tn.read_very_eager().decode("utf-8", errors="ignore")
    tn.close()
    return output


def _run_command_pfsense(gns3_ip: str, port: int, command: str) -> str:
    tn = telnetlib.Telnet(gns3_ip, port, 15)
    time.sleep(2)
    tn.write(b"\r\n")
    time.sleep(1)
    tn.write(b"8\r\n")   # Shell option form pfSense menu
    time.sleep(2)
    tn.write(command.encode("ascii") + b"\r\n")
    time.sleep(3)
    output = tn.read_very_eager().decode("utf-8", errors="ignore")
    tn.write(b"exit\r\n")
    time.sleep(1)
    tn.close()
    return output


def _resolve(text: str, context: dict) -> str:
    for key, value in context.items():
        text = text.replace(f"{{{{{key}}}}}", value)
    return text


def verify(context: dict, lab_rules: dict, get_console_fn, gns3_ip: str) -> bool:
    results = {}

    for check_group in lab_rules["verify"]:
        node      = check_group["node"]
        command   = check_group["command"]
        node_type = lab_rules["nodes"][node]["type"]

        port, _ = get_console_fn(node)
        if port is None:
            print(f"  [ERR] Couldn.t connect to {node}")
            for check in check_group["checks"]:
                results[_resolve(check["label"], context)] = False
            continue

        try:
            if node_type == "pfsense":
                output = _run_command_pfsense(gns3_ip, port, command)
            else:
                output = _run_command(gns3_ip, port, command)
        except Exception as e:
            print(f"  [ERR] Telnet {node}:{port} -> {e}")
            for check in check_group["checks"]:
                results[_resolve(check["label"], context)] = False
            continue

        for check in check_group["checks"]:
            label = _resolve(check["label"], context)
            ok    = True

            if "contains" in check:
                ok = ok and (_resolve(check["contains"], context) in output)

            if "also_contains" in check:
                ok = ok and (_resolve(check["also_contains"], context) in output)

            if "not_contains" in check:
                ok = ok and (_resolve(check["not_contains"], context) not in output)

            results[label] = ok

    print("\n-- Validating solution --")
    all_ok = True
    for label, ok in results.items():
        print(f"  [{'OK' if ok else 'FAIL'}] {label}")
        if not ok:
            all_ok = False

    print(f"\n  {'[SUCCES] Correct!' if all_ok else '[FAIL] Incomplete!'}")
    return all_ok