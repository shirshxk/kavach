
# KAVACH 
![KAVACH LOGO](https://github.com/shirshxk/kavach/blob/main/assets/logofull.png)
Kavach is a real-time packet filtering firewall written in Python using Scapy and NetfilterQueue. It provides both a command-line interface (CLI) and a modern graphical interface (GUI) built with PyQt5, allowing for dynamic rule management, live packet monitoring, and security logging.

---

![Python](https://img.shields.io/badge/Python-3.10+-blue) ![License](https://img.shields.io/badge/License-Educational-lightgrey) ![Platform](https://img.shields.io/badge/Platform-Linux-orange)

## OVERVIEW

- Real-time firewall that hooks into Linux iptables using NetfilterQueue
- GUI and CLI interfaces supported
- Allows and blocks packets based on custom rule engine
- Tracks traffic statistics (total, allowed, blocked)
- Supports IP/subnet, port, and action-based rules
- Fully theme-customizable PyQt5 GUI
- Graph-based live traffic monitor using pyqtgraph
- Proper teardown of firewall hook even on GUI close

---

## RUNTIME ARCHITECTURE
### CLI & GUI
```mermaid
flowchart TD
    Start[User Launches CLI or GUI]

    %% Entry points
    Start --> CLI[main.py - CLI Entry]
    Start --> GUI[gui_app.py - PyQt GUI Entry]

    %% CLI Route
    CLI --> ArgParser[Parse CLI Arguments]
    ArgParser -->|--start / --view-live| InitFirewall[Initialize Rule Engine, Packet Filter, Logger]
    ArgParser -->|--start| NFQ[Set iptables to NFQUEUE]
    NFQ --> PacketRoute[Bind NetfilterQueue and process packet]
    PacketRoute --> PacketFilterCall[Check packet using PacketFilter]
    PacketFilterCall --> RuleEngine[Match rules and apply rate limit]
    RuleEngine --> Verdict[ALLOW or BLOCK verdict]
    Verdict --> Action[Accept or Drop the packet]
    Verdict --> Log[Write action to log file]

    %% Traffic Monitor
    ArgParser -->|--monitor-traffic| Monitor[Call get_traffic_statistics function]
    Monitor --> DisplayStats[Display packet and byte stats]

    %% CLI Rule Management
    ArgParser -->|--add-rule| AddRule[Add rule to RuleEngine and save JSON]
    ArgParser -->|--remove-rule| RemoveRule[Remove rule from RuleEngine]
    ArgParser -->|--list-rules| ListRules[List rules from file]

    %% CLI Exit or Exception
    ArgParser -->|--run-tests| RunTests[Run all unit tests]
    ArgParser -->|--reset-rules| ResetRules[Clear all rules in RuleEngine]

    %% GUI Route
    GUI --> UnifiedMain[UnifiedMain class - Qt GUI]
    UnifiedMain --> GUIComponents[UI: Table, Graph, Rule Panel]
    UnifiedMain --> GUILogic[Rule Management Add/Remove/List]
    UnifiedMain --> GUIButtons[Start or Stop Firewall with NFQUEUE]
    GUIButtons --> GUILoop[Loop: process packet and filter it]
    GUILoop --> VerdictEmitter[Emit verdict using verdict_emitter]
    VerdictEmitter --> GUIUpdate[Update UI components]
    GUIUpdate --> Log

    %% Shared Blocks
    InitFirewall --> RuleEngine
    InitFirewall --> PacketFilter
    InitFirewall --> Logger

    %% Cleanup Paths
    Action -->|KeyboardInterrupt| Cleanup[Remove iptables NFQUEUE rule]
    GUIButtons -->|Stop Clicked| Cleanup

    %% === Styling ===
    style Start fill:#222,color:white

    %% CLI Section
    style CLI fill:#2e2e2e,color:white
    style ArgParser fill:#3a3a3a,color:white
    style InitFirewall fill:#444,color:white
    style NFQ fill:#4b4b4b,color:white
    style PacketRoute fill:#4b4b4b,color:white
    style PacketFilterCall fill:#5a5a5a,color:white
    style RuleEngine fill:#666,color:white
    style Verdict fill:#777,color:white
    style Action fill:#888,color:white
    style Log fill:#999,color:white

    style Monitor fill:#3a3a3a,color:white
    style DisplayStats fill:#444,color:white

    style AddRule fill:#3a3a3a,color:white
    style RemoveRule fill:#3a3a3a,color:white
    style ListRules fill:#3a3a3a,color:white
    style RunTests fill:#3a3a3a,color:white
    style ResetRules fill:#3a3a3a,color:white

    %% GUI Section
    style GUI fill:#2e2e2e,color:white
    style UnifiedMain fill:#444,color:white
    style GUIComponents fill:#4e4e4e,color:white
    style GUILogic fill:#555,color:white
    style GUIButtons fill:#5c5c5c,color:white
    style GUILoop fill:#666,color:white
    style VerdictEmitter fill:#777,color:white
    style GUIUpdate fill:#888,color:white

    %% Shared & Cleanup
    style Cleanup fill:#aa0000,color:white
    style InitFirewall fill:#444,color:white

```

### CLI
```mermaid
---
config:
  layout: dagre
---
flowchart TD
    A["CLI Entry Point: main.py"] --> B["ArgumentParser - CustomArgumentParser"]
    B --> C1["Start Mode - s"] & C2["View Mode - v"] & C3["Add Rule - a"] & C4["Remove Rule - r"] & C5["List Rules - l"] & C6["Monitor Traffic - m"] & C7["Run Tests - u"] & C8["Version Info - i"] & C9["Reset Rules - d"]
    C1 --> D1["initialize_firewall"] & F["NetfilterQueue Binding"]
    C2 --> D1 & I["PacketSniffer"]
    D1 --> E1["RuleEngine"] & E2["PacketFilter"] & E3["Logger - firewall.log"]
    F --> G["process_packet"]
    G --> H["Scapy Packet Decoding"] & E2
    I --> E2
    C3 --> J1["Helper.parse_rule_arg"]
    J1 --> E1
    C4 --> J2["Helper.parse_rule_arg or parse_ports"]
    J2 --> E1
    C5 --> E1
    C6 --> K["Helper.detect_interface"]
    K --> L["get_traffic_statistics"]
    L --> M["psutil net_io_counters + socket if_addrs"]
    C7 --> N["test_firewall.py, test_logger.py, test_sniffer.py, etc."]
    E1 --> O["default_rules.json"]
    E2 --> E3
    style A fill:#222,color:white
    style B fill:#333,color:white
    style C1 fill:#444,color:white
    style C2 fill:#444,color:white
    style C3 fill:#444,color:white
    style C4 fill:#444,color:white
    style C5 fill:#444,color:white
    style C6 fill:#444,color:white
    style C7 fill:#444,color:white
    style C8 fill:#444,color:white
    style C9 fill:#444,color:white
    style D1 fill:#2a2a2a,color:white
    style F fill:#555,color:white
    style I fill:#666,color:white
    style E1 fill:#2d2d2d,color:white
    style E2 fill:#2e2e2e,color:white
    style E3 fill:#2f2f2f,color:white
    style G fill:#666,color:white
    style H fill:#777,color:white
    style J1 fill:#3a3a3a,color:white
    style J2 fill:#3a3a3a,color:white
    style K fill:#383838,color:white
    style L fill:#484848,color:white
    style M fill:#585858,color:white
    style N fill:#3c3c3c,color:white
    style O fill:#2b2b2b,color:white
```

### GUI

```mermaid
graph TD
    A[GUI Application: UnifiedMain] --> B[RuleEngine]
    A --> C[PacketFilter]
    A --> D[NetfilterQueue Binding]
    D --> E[VerdictEmitter Signal]
    E --> F[append_traffic_row - GUI Table + Stats]

    B --> G[default_rules.json]
    C --> H[Logger - firewall.log]

    A --> I[Helper Functions]
    A --> J[PyQtGraph Live Monitor]

    style A fill:#222,color:white
    style B fill:#333,color:white
    style C fill:#444,color:white
    style D fill:#555,color:white
    style E fill:#666,color:white
    style F fill:#777,color:white
    style G fill:#2d2d2d,color:white
    style H fill:#2a2a2a,color:white
    style I fill:#383838,color:white
    style J fill:#444,color:white
```

## FEATURES

### CORE

- IP / Subnet-based rule enforcement
- Source port validation
- Packet verdicts emitted in real time to GUI
- Persistent rule store (`default_rules.json`)
- Log tracking to `logs/firewall.log`
- Modular components (`rule_engine`, `packet_filter`, `packet_sniffer`, `logger`, `verdict_log`, etc.)

### GUI (PyQt5)

- Rule Management (Add, Remove, List)
- Input fields for IP, Port, Action
- Live updating QTableWidget showing traffic
- Traffic counters: total, allowed, blocked
- Real-time line graph for traffic (allowed/blocked)
- Start/Stop Firewall buttons with status
- Output panel for logs and feedback
- CloseEvent safely unbinds NFQUEUE

### CLI

- CLI rule control using flags
- Start and stop NFQUEUE-based firewall
- Dynamic rule additions/removals
- Argument validation using helpers

---

## 🔧 Installation

First, clone the repository and navigate into the project directory:

```bash
git clone https://github.com/shirshxk/kavach.git
cd kavach
```

Then, run the setup script to automatically install all required dependencies and configure CLI aliases:

```bash
sudo python3 setup.py
```

> This script installs packages listed in `requirements.txt` and creates convenient aliases:  
> `kavach` for the CLI tool and `kavachgui` for the GUI version.

If the aliases do not take effect immediately, restart your terminal or run `source ~/.bashrc` (or `~/.zshrc` depending on your shell).

## 📦 Dependencies

These are installed automatically by the setup script, but for reference:

```
PyQt5
pyqtgraph
scapy
netfilterqueue
psutil
colorama
tqdm
```

## 🚀 Usage

### GUI Mode

```bash
kavachgui
```

Or if you want to run it manually:

```bash
cd gui
sudo ./gui_app.py
```

### CLI Mode

Start the firewall:

```bash
kavach --start
```

View traffic live (no blocking):

```bash
kavach --view-live
```

Add a rule:

```bash
kavach -a "192.168.1.5,BLOCK"
```

Remove a rule:

```bash
kavach -r "192.168.1.5,BLOCK"
```

List all rules:

```bash
kavach -l
```

Block ports:

```bash
kavach -p "22,80,443"
```

Monitor traffic for 10 seconds (default):

```bash
kavach -m
```

Reset all rules:

```bash
kavach -d
```

Run unit tests:

```bash
kavach -u
```

Check version:

```bash
kavach -i
```

## RULE FORMAT

JSON rule structure:

```json
{
    "src": "192.168.1.0/24",
    "sport": 22,
    "action": "BLOCK"
}
```

- `src`: IP or subnet (CIDR supported)
- `sport`: Source port (optional)
- `action`: ALLOW or BLOCK

---

## LOGGING

All packet verdicts (ALLOW/BLOCK) are logged to:

```
logs/firewall.log
```

Example:

```
[2025-07-13 13:45:02] BLOCK 192.168.1.10:443 -> 10.0.0.1:80 TCP
[2025-07-13 13:45:06] ALLOW 192.168.1.11:1234 -> 10.0.0.1:22 UDP
```

---

## CODE STRUCTURE

```
firewall/
├── main.py
├── setup.py
├── gui/
│   ├── gui_app.py
│   ├── state.py
│   ├── verdict_log.py
│   └── unified_main.py
├── src/
│   ├── core/
│   │   ├── configs/
│   │   │   └── default_rules.json
│   │   ├── packet_sniffer.py
│   │   ├── packet_filter.py
│   │   ├── rule_engine.py
│   │   └── logger.py
│   └── utils/
│       └── helpers.py
├── logs/
│   └── firewall.log
├── tests/
│   └── test_*.py
├── logo.png
└── requirements.txt
```

---

## LICENSE

This project is licensed for educational and research purposes only, developed under the ST5062CEM Programming and Algorithm 2 module (Softwarica College).

---

## CREDITS

Developed by Shirshak Shrestha for coursework submission, July 2025

Course: Programming & Algorithm 2  
Module Code: ST5062CEM  
Instructor: Suman Shrestha
