# CSW Blast Radius Demo

**Automated environment builder for Cisco Secure Workload segmentation enforcement demos.**

This tool builds a complete, repeatable blast radius demonstration in five independently controlled phases. Every phase is a deliberate choice. The enforcement moment is always a manual trigger so you control the live beat in front of a customer.

---

## The Story

A compromised workload sitting inside your network is far more dangerous than anything knocking at the perimeter. The question every customer should be asking is not "can someone get in?" but "if something gets in, how far can it go?"

This demo answers that question live. Before enforcement, a workload can reach anything it wants. After enforcement, Cisco Secure Workload collapses the blast radius to a single allowed path. The customer watches it happen in real time -- in the traffic simulator terminal, on the CSW Global Visualization Canvas, and at the host firewall level on the VMs themselves.

---

## What You Need

| Requirement | Notes |
|---|---|
| Python 3.9+ | `python3 --version` |
| Two Linux VMs | With CSW enforcement agents installed |
| SSH key | Added to each VM's `authorized_keys` |
| CSW SaaS instance | With API access |
| CSW agent installer | Downloaded once from the CSW UI |
| macOS or Linux | `ssh` and `scp` must be in PATH |

### SSH key setup

```bash
# Create a dedicated key for lab access
ssh-keygen -t ed25519 -C "csw-lab" -f ~/.ssh/csw_lab_key

# Copy to each VM (run once per VM, uses password this one time)
ssh-copy-id -i ~/.ssh/csw_lab_key.pub beghorra@<VM_IP>
```

For passwordless operation during the demo, add the key to macOS Keychain:

```bash
ssh-add --apple-use-keychain ~/.ssh/csw_lab_key
```

Add this to `~/.zshrc` so it survives reboots:

```bash
ssh-add --apple-use-keychain ~/.ssh/csw_lab_key 2>/dev/null
```

### Agent installer download

The installer script embeds your tenant address and TLS certificate. Download it once:

1. Log into your CSW instance
2. Navigate to Manage > Agents > Installer tab
3. Choose: Agent Script Installer > Linux > Enforcement > No Expiration
4. Save as `tetration_installer.sh` in this folder

This file is excluded from Git by `.gitignore` since it is tenant-specific.

---

## Setup

```bash
# 1. Clone the repo
git clone https://github.com/your-org/csw-blast-radius-demo.git
cd csw-blast-radius-demo

# 2. Create your credentials file
cp .env.example .env
# Edit .env -- add CSW_API_KEY, CSW_API_SECRET, CSW_TENANT

# 3. Edit config.yaml
# Set your VM IPs, hostnames, SSH key path, scope names, and mgmt IP
```

### config.yaml key values

```yaml
csw:
  tenant: "your-tenant.tetrationcloud.com"
  root_scope_name: "YOUR_ROOT_SCOPE"

ssh:
  key_path: "~/.ssh/csw_lab_key"
  user: "your_username"

vms:
  - ip: "10.x.x.x"
    hostname: "vm-app"
    role: "app"
    env: "lab-demo"
    ssh_user: "your_username"

  - ip: "10.x.x.x"
    hostname: "vm-db"
    role: "db"
    env: "lab-demo"
    ssh_user: "your_username"

demo:
  scope_name: "BRD-Lab"
  parent_scope_name: "YourParentScope"
  workspace_name: "Blast Radius Demo Policy"
  allowed_port: 5432       # app -> db (the one allowed path)
  mgmt_ip: "x.x.x.x"      # your Mac IP (gets SSH access to both VMs)
  mgmt_port: 22            # what your Mac is allowed on
```

---

## Running the Demo

```bash
python3 menu.py
```

### Menu reference

```
  Phases
  ──────────────────────────────────────────────────
  1  Create scope + upload labels to CSW
  2  Deploy agents to lab VMs (SSH)
  3  Create workspace + policy + start analysis
  4  ENFORCE  (live demo moment -- lock the doors)
  5  Teardown (clean up after demo)

  Utilities
  ──────────────────────────────────────────────────
  TE  Traffic simulator -- External  (Mac -> VMs, perimeter view)
  TI  Traffic simulator -- Internal  (vm-app -> vm-db, lateral movement)
  TC  Traffic simulator -- Combined  (both perspectives, recommended)
  N   Show nftables rules on VMs    (run before + after enforcement)
  S   Show environment status
  A   Auto prep -- run phases 1, 2, 3 in sequence
  Q   Quit
```

---

## The Five Phases

### Phase 1 -- Scope and Labels

Uploads labels to each VM via the CSW inventory tags API, then creates a child scope using a label-based query. No IP addresses in the scope definition -- workloads are identified by what they are, not where they sit.

Labels applied to each VM:
- `Application = DemoBRD` (scope query anchor)
- `role = app | db` (used in workspace policy filters)
- `hostname = <vm hostname>`

### Phase 2 -- Agent Deployment

SSHes into each VM and runs the CSW enforcement agent installer. Skips VMs where the agent is already installed. Polls the CSW sensors API until all agents check in as active.

Requires `eval "$(ssh-agent -s)" && ssh-add ~/.ssh/csw_lab_key` in your terminal session, or the `--apple-use-keychain` setup described above.

### Phase 3 -- Workspace and Policy

Creates the primary workspace for the demo scope with three absolute policies and a catch-all deny:

| Consumer | Provider | Port | Action |
|---|---|---|---|
| app VM | db VM | TCP/5432 | ALLOW |
| management Mac | app VM | TCP/22 | ALLOW |
| management Mac | db VM | TCP/22 | ALLOW |
| everything else | everything else | any | DENY |

Starts live policy analysis so escaped flows appear in the CSW UI before enforcement -- the "we can see the footprints, but the door is still open" moment.

Why absolute policies? The demo environment is fresh with no ADM history. Absolute policies let us define intent directly without waiting for traffic to be observed and learned. The management SSH rule also requires an IP-based filter since the Mac has no CSW agent, which ADM would never discover.

### Phase 4 -- Enforce

The live moment. Always requires typing `ENFORCE` explicitly -- no accidental fat-finger enforcement in front of a customer.

Reads the current `analyzed_version` from the workspace and passes it explicitly to the enforce API. This works on first enforcement (`p1`) or after any subsequent policy changes (`p5`, `p12`) without ever hardcoding a version number.

### Phase 5 -- Teardown

Cleans up in dependency order: disable enforcement, delete inventory filters, delete workspace, delete scope. Optionally uninstalls agents from VMs.

Filter deletion uses exact name matching (`demo-app`, `demo-db`, `demo-mgmt-mac`) to avoid touching any other filters on a shared tenant.

---

## The Traffic Simulator

The simulator tells the blast radius story from two perspectives simultaneously.

### External mode (TE)

Probes VM ports directly from your Mac. Shows the perimeter view -- what an outside attacker sees. After enforcement, only TCP/22 (management SSH) survives from the Mac. TCP/5432 is blocked even from your Mac because the policy only allows the app VM to reach the db VM on that port.

### Internal mode (TI)

SSHes into the app VM and runs `nc` probes from there to the db VM. This is the real story -- a compromised workload trying to pivot laterally. Before enforcement, everything is reachable from inside. After enforcement, CSW drops traffic at the host firewall on the db VM. Even a workload already inside the environment cannot reach what it should not.

### Combined mode (TC)

Both perspectives in one terminal, alternating rounds. Recommended for live demos.

### NFTables view (N)

SSHes into each VM and displays the firewall rules CSW has written to the host. Run before enforcement to show an open state. Run after enforcement to show the rules that were actually pushed. This is your most concrete proof -- the customer can see the policy at the OS level, not just in the CSW UI.

---

## Demo Day Sequence

**Night before:**
```bash
python3 menu.py
# Choose A -- runs phases 1, 2, 3 unattended
```

**Day of, before the call:**
```bash
python3 menu.py
# Choose S -- verify all green: agents active, scope exists, workspace exists
# Choose N -- show the open nftables state (screenshot this for the before/after)
```

**Two terminals open when the customer joins:**

Terminal 1:
```bash
python3 traffic/simulator.py --config config.yaml --mode combined
```

Terminal 2:
```bash
python3 menu.py
# Sitting at the menu, ready
```

Browser: CSW > Defend > Segmentation > your workspace > Policy Analysis

**The moment:**
```bash
# In Terminal 2
# Choose 4 -> type ENFORCE -> press Enter
# Watch both screens flip simultaneously
```

**After the demo:**
```bash
python3 menu.py
# Choose N -- show the enforced nftables state
# Choose 5 -- teardown
```

---

## Non-Interactive Usage

```bash
# Run a specific phase directly
python3 menu.py --phase 1
python3 menu.py --phase 4

# Run prep phases in sequence (no enforcement)
python3 menu.py --phase all

# Run simulator in a specific mode
python3 traffic/simulator.py --mode internal
python3 traffic/simulator.py --mode nftables
```

---

## Project Structure

```
csw-blast-radius-demo/
├── menu.py                       # Interactive control center
├── config.yaml                   # Environment config (safe to commit)
├── .env.example                  # Credential template
│
├── auth/
│   └── csw_client.py             # HMAC-SHA256 signing client
│
├── phases/
│   ├── phase1_scope_labels.py    # Label upload + scope creation
│   ├── phase2_agent_deploy.py    # SSH agent installation
│   ├── phase3_workspace_policy.py # Workspace + absolute policies
│   ├── phase4_enforce.py         # Policy enforcement
│   └── phase5_teardown.py        # Environment cleanup
│
└── traffic/
    └── simulator.py              # Multi-mode traffic simulator
```

---

## CSW API Authentication

This tool uses HMAC-SHA256 signing. The verified pattern:

```
Timestamp : YYYY-MM-DDTHH:MM:SS+0000
Checksum  : SHA256 hex of body (empty string for GET/DELETE)
String to sign: METHOD\nPATH\nCHECKSUM\napplication/json\nTIMESTAMP\n
Signature : base64(HMAC-SHA256(api_secret, string_to_sign))
Headers   : Id, Authorization, Timestamp, Content-Type, X-Tetration-Cksum
```

Credentials are read exclusively from environment variables. Never hardcoded.

---

## API Capabilities Required

Your CSW API key needs:
- `app_policy_management` -- scopes, workspaces, policies, enforcement
- `user_data_upload` -- inventory label upload
- `sensor_management` -- agent status queries

---

## License

Apache 2.0
