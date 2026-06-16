import json
import os
import requests
import time
import telnetlib
import re
from generate_ex import build, load_lab_rules

GNS3_IP     = "192.168.7.134"
API_KEY     = "NYijpP1ysY4NkDPdY7GdAN8PvsjbfwVn"
URL_MISTRAL = "https://api.mistral.ai/v1/chat/completions"

FILE_TO_TEST ="arp_spoof_attack-template.json"


def lab_id_from_filename(filename: str) -> str:
    return filename.replace("-template.json", "").replace(".json", "")

# LLM 

def load_scenario_from_file(filename: str) -> dict:
    path = os.path.join("scenarios", filename)
    if not os.path.exists(path):
        path = filename
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def get_ai_response(template_data: dict) -> dict:
    llm_prompt = (
        "CONTEXT: You are a Networking and Cybersecurity Lab Architect. "
        "Your task is to transform a static template into a dynamic, unique lab scenario."
        "\n\nSTEP-BY-STEP PROCESS:"
        "\n1. GENERATE unique values for all keys in 'generation_rules' (diverse IPs, random MACs NOT starting with 00:1a, unique departments)."
        "\n2. RE-WRITE the 'base_template' story from scratch. Do NOT just copy the instruction. Create a professional narrative (e.g., incident report, sysadmin log, or user ticket)."
        "\n3. INJECT the generated values from step 1 into your new story, replacing all {{placeholders}}."
        "\n\nSTRICT RULES:"
        "\n- CREATIVITY: Be creative. Think of different and creative industries (Healthcare, Aerospace, Finance)."
        "\n- MAC ADDRESSES: Use diverse vendor prefixes (e.g., 08:00:27, 44:AD:D9, 00:50:56)."
        "\n- NO PLACEHOLDERS: If I see '{{' or '}}' in the final 'base_template', the task is a failure."
        "\n- CLEAN JSON: Return ONLY the raw JSON. No markdown blocks, no conversational filler."
        "\n- OBJECT REPLACEMENT: Every key that was an object with an 'instruction' MUST become a plain STRING with the result."
        "\n- BASE_TEMPLATE: Must be a plain STRING, never a JSON object or nested dict."
        "\n- Do NOT add extra keys outside of the original template structure."
    )

    payload = {
        "model": "mistral-small-latest",
        "temperature": 0.8,
        "messages": [
            {"role": "system", "content": llm_prompt},
            {"role": "user",   "content": f"Seed ID: {time.time()}. Using this template: {json.dumps(template_data)}, generate a completely new instance."}
        ],
        "response_format": {"type": "json_object"}
    }

    response = requests.post(
        URL_MISTRAL,
        json=payload,
        headers={"Authorization": f"Bearer {API_KEY}", "Content-Type": "application/json"}
    )
    response.raise_for_status()
    return json.loads(response.json()["choices"][0]["message"]["content"])


def validate_result(result: dict) -> bool:
    base = result.get("base_template", "")
    if isinstance(base, dict):
        base = json.dumps(base)
    if "{{" in base or "}}" in base:
        print("[WARN] LLM left unresolved placeholders in base_template!")
        print(base)
        return False
    return True


def validate_lab_rules(lab_rules: dict, template_data: dict) -> bool:
    """
    Two-step verification:
    1. All placeholders in config_templates/<lab_id>/ have a source in lab_rules (from_llm or derived)
    2. All keys in from_llm appear in generation_rules of the scenario template
    """
    lab_id  = lab_rules["lab_id"]
    all_ok  = True

    # build the set of available keys in context
    available = set(lab_rules["build"]["from_llm"])
    for rule in lab_rules["build"]["derived"]:
        available.add(rule["key"])

    print(f"\n-- Validating lab rules: {lab_id} --")
    print(f"  Available keys in context: {sorted(available)}")

    #  Check 1 
    # All placeholders in config_templates have a source in context
    print("\n  [Check 1] config_templates placeholders:")
    templates_dir = os.path.join("config_templates", lab_id)
    for node, node_cfg in lab_rules["nodes"].items():
        path = os.path.join(templates_dir, node_cfg["template"])
        if not os.path.exists(path):
            print(f"  [ERR] Template missing: {path}")
            all_ok = False
            continue

        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        placeholders = set(re.findall(r"\{\{(\w+)\}\}", content))
        for ph in placeholders:
            if ph not in available:
                print(f"  [ERR] {node} ({node_cfg['template']}): {{{ph}}} has no defined source")
                all_ok = False
            else:
                print(f"  [OK]  {node} ({node_cfg['template']}): {{{ph}}} → ok")

    # Check 2 
    # All placeholders in config_templates have a source in context
    print("\n  [Check2] from_llm keys present in generation_rules of template:")
    template_keys = set(template_data.get("generation_rules", {}).keys())
    for key in lab_rules["build"]["from_llm"]:
        if key not in template_keys:
            print(f"  [ERR] '{key}' exists in from_llm but is missing in generation_rules of template")
            all_ok = False
        else:
            print(f"  [OK]  '{key}' exists in generation_rules")

    print(f"\n  {'[VALID] Lab rules are correct.' if all_ok else '[INVALID] Lab rules incomplete.'}")
    return all_ok


#  Config generation 

def render_template(template_str: str, context: dict) -> str:
    for key, value in context.items():
        template_str = template_str.replace(f"{{{{{key}}}}}", value)
    return template_str


def generate_configs(lab_rules: dict, context: dict) -> dict:
    configs = {}
    templates_dir = os.path.join("config_templates", lab_rules["lab_id"])
    for node, node_cfg in lab_rules["nodes"].items():
        path = os.path.join(templates_dir, node_cfg["template"])
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
        configs[node] = render_template(raw, context)
    return configs


def save_configs(configs: dict, lab_id: str):
    output_dir = os.path.join("generated_configs", lab_id)
    os.makedirs(output_dir, exist_ok=True)
    for node, config in configs.items():
        path = os.path.join(output_dir, f"{node}.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(config)
        print(f"  [SAVE] {node} -> {path}")


#  GNS3 API 

def get_node_console(node_name: str, project_id: str):
    url = f"http://{GNS3_IP}/v2/projects/{project_id}/nodes"
    try:
        for node in requests.get(url, timeout=5).json():
            if node["name"] == node_name:
                return node.get("console"), node.get("console_type", "telnet")
    except Exception as e:
        print(f"  [ERR] GNS3 API: {e}")
    return None, None


def get_node_id(node_name: str, project_id: str) -> str:
    url = f"http://{GNS3_IP}/v2/projects/{project_id}/nodes"
    try:
        for node in requests.get(url, timeout=5).json():
            if node["name"] == node_name:
                return node["node_id"]
    except Exception as e:
        print(f"  [ERR] GNS3 API: {e}")
    return None


def get_node_coordinates(node_name: str, project_id: str):
    url = f"http://{GNS3_IP}/v2/projects/{project_id}/nodes"
    try:
        for node in requests.get(url, timeout=5).json():
            if node["name"] == node_name:
                return node["x"], node["y"]
        print(f"  [!] Node '{node_name}' not found.")
    except Exception as e:
        print(f"  [ERR] GNS3 API: {e}")
    return None, None


def add_vlan_label(text: str, x_pos, y_pos, project_id: str):
    url = f"http://{GNS3_IP}/v2/projects/{project_id}/drawings"
    payload = {
        "x": int(x_pos), "y": int(y_pos), "z": 1,
        "svg": f"<svg><text font-family='Arial' font-size='18' font-weight='bold' fill='blue'>{text}</text></svg>"
    }
    try:
        requests.post(url, json=payload, timeout=5)
    except Exception as e:
        print(f"  [ERR] Drawing: {e}")


def clear_drawings(project_id: str):
    url = f"http://{GNS3_IP}/v2/projects/{project_id}/drawings"
    try:
        drawings = requests.get(url, timeout=5).json()
        for drawing in drawings:
            requests.delete(f"{url}/{drawing['drawing_id']}", timeout=5)
        print(f"  [OK] {len(drawings)} labels deleted")
    except Exception as e:
        print(f"  [ERR] Clear drawings: {e}")


def apply_dynamic_labels(result_json: dict, template_json: dict, project_id: str):
    rules            = template_json.get("generation_rules", {})
    generated_values = result_json.get("generation_rules", {})
    for key, value in generated_values.items():
        rule_data = rules.get(key)
        if isinstance(rule_data, dict) and "anchor_node" in rule_data:
            node_name = rule_data["anchor_node"]
            x, y = get_node_coordinates(node_name, project_id)
            if x is not None:
                label_text = value.get("value", str(list(value.values())[0])) if isinstance(value, dict) else str(value)
                add_vlan_label(label_text, x, y - 80, project_id)
                print(f"  [UI] Label '{label_text}' placed above {node_name}")


#  Telnet push 

def push_cisco_config(host: str, port: int, config_text: str, timeout: int = 15) -> bool:
    skip = {"end", ""}
    lines = [
        ln.strip() for ln in config_text.splitlines()
        if ln.strip() and not ln.strip().startswith("!")
        and ln.strip().lower() not in skip
    ]
    try:
        tn = telnetlib.Telnet(host, port, timeout)
        time.sleep(2)
        
        tn.write(b"\r\n")
        time.sleep(1)
        tn.write(b"no\r\n") 
        time.sleep(2)  
        tn.write(b"\r\n")
        time.sleep(1)
        
        tn.write(b"enable\r\n")
        time.sleep(1)
        tn.write(b"configure terminal\r\n")
        time.sleep(1)
        
        for line in lines:
            tn.write(line.encode("ascii") + b"\r\n")
            time.sleep(0.2)  
            
        tn.write(b"end\r\n")
        time.sleep(1)
        tn.write(b"write memory\r\n")
        time.sleep(3) 
        tn.write(b"\r\n")
        time.sleep(1)
        tn.close()
        return True
    except Exception as e:
        print(f"  [ERR] Telnet Cisco {host}:{port} -> {e}")
        return False



def push_vpcs_config(host: str, port: int, config_text: str, timeout: int = 10) -> bool:
    lines = [
        ln.strip() for ln in config_text.splitlines()
        if ln.strip() and not ln.strip().startswith("!")
    ]
    try:
        tn = telnetlib.Telnet(host, port, timeout)
        time.sleep(1)
        for line in lines:
            tn.write(line.encode("ascii") + b"\r\n")
            time.sleep(1)
        tn.close()
        return True
    except Exception as e:
        print(f"  [ERR] Telnet VPCS {host}:{port} -> {e}")
        return False


def push_alma_config(host: str, port: int, config_text: str, timeout: int = 10) -> bool:
    lines = [
        ln.strip() for ln in config_text.splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    try:
        tn = telnetlib.Telnet(host, port, timeout)
        time.sleep(2)
        tn.write(b"\r\n")
        time.sleep(1)
        # kills old procs
        tn.write(b"pkill arpspoof\r\n")
        time.sleep(1)
        for line in lines:
            tn.write(line.encode("ascii", errors="ignore") + b"\r\n")
            time.sleep(0.5)
        tn.close()
        return True
    except Exception as e:
        print(f"  [ERR] Telnet Alma {host}:{port} -> {e}")
        return False


def push_configs_to_gns3(lab_rules: dict, configs: dict):
    project_id = lab_rules["project_id"]
    for node_name, config in configs.items():
        node_type = lab_rules["nodes"][node_name]["type"]
        port, _   = get_node_console(node_name, project_id)
        if port is None:
            print(f"  [WARN] Console port not found for {node_name}")
            continue

        print(f"  [PUSH] {node_name} (telnet :{port}) ...")

        if node_type == "cisco":
            ok = push_cisco_config(GNS3_IP, port, config)
        elif node_type == "vpcs":
            ok = push_vpcs_config(GNS3_IP, port, config)
        elif node_type == "alma":
            ok = push_alma_config(GNS3_IP, port, config)
        else:
            print(f"  [SKIP] {node_name} - type unknown")
            continue

        print(f"  [{'OK' if ok else 'ERR'}] {node_name}")
        
def wait_for_nodes_ready(lab_rules: dict, configs: dict, timeout: int = 120, poll_interval: int = 5):
    """Waits for Cisco nodes, max timeout seconds."""
    project_id = lab_rules["project_id"]
    cisco_nodes = [n for n, cfg in lab_rules["nodes"].items() 
                   if cfg["type"] == "cisco" and n in configs]
    
    pending = set(cisco_nodes)
    deadline = time.time() + timeout
    
    print(f"  [WAIT] Wait booting for {len(pending)} nodes (max {timeout}s)...")
    
    while pending and time.time() < deadline:
        for node_name in list(pending):
            port, _ = get_node_console(node_name, project_id)
            if not port:
                continue
            try:
                tn = telnetlib.Telnet(GNS3_IP, port, timeout=3)
                tn.write(b"\r\n")
                time.sleep(1)
                output = tn.read_very_eager().decode("utf-8", errors="ignore")
                tn.close()
                
                # node is ready if prompt is available
                if ">" in output or "#" in output:
                    print(f"  [OK]  {node_name} ready ({int(time.time() - (deadline - timeout))}s)")
                    pending.discard(node_name)
            except Exception:
                pass
        
        if pending:
            time.sleep(poll_interval)
    
    if pending:
        print(f"  [WARN] Timeout! Nodes not responding {pending}")
    else:
        print(f"  [OK]  All nodes ready.")
        

def _clean_dhcp(tn, send_wait):
    tn.write(b"show running-config | include ip dhcp excluded-address\r\n")
    time.sleep(2)
    raw = b""
    deadline = time.time() + 10
    while time.time() < deadline:
        chunk = tn.read_very_eager()
        raw += chunk
        if b"#" in chunk:
            break
        time.sleep(0.3)

    pairs = re.findall(
    r"ip dhcp excluded-address (\d+\.\d+\.\d+\.\d+)(?:\s+(\d+\.\d+\.\d+\.\d+))?",
    raw.decode("utf-8", errors="ignore") 
)
    print(f"  [DEBUG] pairs found: {pairs}")  

    if pairs:
        send_wait("configure terminal", 0.5)
        for ip1, ip2 in pairs:
            cmd = f"no ip dhcp excluded-address {ip1} {ip2}".strip() if ip2 else f"no ip dhcp excluded-address {ip1}"
            send_wait(cmd, 0.2)
        send_wait("end", 0.5)


def reset_all_nodes(lab_rules: dict, configs: dict):
    project_id  = lab_rules["project_id"]
    cisco_nodes = {n for n, cfg in lab_rules["nodes"].items() if cfg["type"] == "cisco"}
    
    print("  [WAIT] Wait for nodes to be ready for cleanup...")
    wait_for_nodes_ready(lab_rules, configs, timeout=60, poll_interval=5)

    for node_name in configs:
        if node_name not in cisco_nodes:
            continue

        port, _ = get_node_console(node_name, project_id)
        node_id  = get_node_id(node_name, project_id)

        if port:
            try:
                tn = telnetlib.Telnet(GNS3_IP, port, 10)
                time.sleep(1)

                def send_wait(cmd: str, delay: float = 1.0):
                    tn.write(cmd.encode("ascii") + b"\r\n")
                    time.sleep(delay)
                    try:
                        tn.read_very_eager()
                    except Exception:
                        pass

                send_wait("\r\n", 0.5)
                send_wait("enable")
                send_wait("configure terminal", 0.5)
                send_wait("no vlan 2-1001", 1.0)
                send_wait("end", 0.5)
                tn.write(b"configure terminal\r\n"); time.sleep(0.5)
                tn.write(b"interface FastEthernet0/0\r\n"); time.sleep(0.2)
                tn.write(b"no ip helper-address\r\n"); time.sleep(0.5)
                tn.write(b"end\r\n"); time.sleep(0.5)

                _clean_dhcp(tn, send_wait)

                send_wait("write memory", 3.0)
                tn.write(b"\r\n"); time.sleep(3)
                tn.write(b"write memory\r\n"); time.sleep(1)
                tn.write(b"\r\n"); time.sleep(1)
                tn.write(b"\r\n"); time.sleep(3) 

                tn.close()
                print(f"  [OK]  {node_name} curatat")

            except Exception as e:
                print(f"  [ERR] Reset {node_name}: {e}")

        if node_id:
            print(f"  [RESET] Stop {node_name}...")
            requests.post(f"http://{GNS3_IP}/v2/projects/{project_id}/nodes/{node_id}/stop", timeout=5)
            time.sleep(3)
            print(f"  [START] {node_name}...")
            requests.post(f"http://{GNS3_IP}/v2/projects/{project_id}/nodes/{node_id}/start", timeout=5)

    wait_for_nodes_ready(lab_rules, configs, timeout=120, poll_interval=5)
    
#  Main 

if __name__ == "__main__":
    try:
        lab_id    = lab_id_from_filename(FILE_TO_TEST)
        lab_rules = load_lab_rules(lab_id)
        project_id = lab_rules["project_id"]
        print(f"[LAB] {lab_id}")
        
        print(f"[0/5] Validating necessary variables: {FILE_TO_TEST}")
        template_data = load_scenario_from_file(FILE_TO_TEST)
        if not validate_lab_rules(lab_rules, template_data):
            exit(1)

        print(f"[1/5] Loading template: {FILE_TO_TEST}")

        print("[2/5] Mistral AI request...")
        result = get_ai_response(template_data)
        with open("instanta_generata.json", "w") as f:
            json.dump(result, f, indent=4)
        print("[OK] instanta_generata.json saved")

        if not validate_result(result):
            print("[ERR] Invalid scenario - rerun script")
            exit(1)

        print("[3/5] Generating configs...")
        context = build(result, lab_rules)
        configs = generate_configs(lab_rules, context)
        save_configs(configs, lab_id)

        print("[4/5] Drawing labels...")
        clear_drawings(project_id)
        apply_dynamic_labels(result, template_data, project_id)

        print("[5/5] Pushing configs to GNS3...")
        reset_all_nodes(lab_rules, configs)    # erase + restart
        push_configs_to_gns3(lab_rules, configs)

        print("\n[SUCCES]")
        
    except Exception as e:
        print(f"\n[ERR]: {e}")