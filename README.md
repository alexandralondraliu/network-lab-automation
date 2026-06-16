# network-lab-automation

Automated generation of networking and cybersecurity lab exercises using Mistral AI and GNS3.

Each run produces a unique scenario with different IP addresses, MAC addresses, and incident narrative. Device configurations are pushed to GNS3 via Telnet, and a verification script checks the student's solution automatically.

## Usage

**Generate a lab:**
```bash
python main.py
```

**Verify the student's solution:**
```bash
python test.py
```

Set `FILE_TO_TEST` in `main.py` to select the active lab, and configure `GNS3_IP` and `API_KEY` with your GNS3 VM address and Mistral AI key.

## Requirements

- Python 3.12+
- GNS3 VM with Cisco IOSv, IOSv-L2, Alma Linux 9 images
- Mistral AI API key

## Adding a New Lab

Create a scenario template in `scenarios/`, a rules file in `labs/`, and configuration templates in `config_templates/<lab_id>/`. No Python changes required.
