# CSW Blast Radius Demo — Stop Lateral Movement with Cisco Secure Workload

Automated, repeatable Cisco Secure Workload (CSW / Tetration) demo that proves
**blast radius containment** — what happens to an attacker who is already
inside your network the moment CSW enforcement turns on.

Built entirely against the CSW REST API in Python, so the same flow that
powers the demo can drop straight into a CI/CD pipeline.

The tool builds the entire scenario for you in five idempotent phases.
Phases 1–3 are safe to run unattended ahead of the call. Phase 4 (the
moment lateral movement stops) is always a deliberate, manual trigger —
no script anywhere can enforce policy by accident.

> **Companion video:** [Stop Lateral Movement: Blast Radius Containment with
> Cisco Secure Workload](https://www.youtube.com/watch?v=_Dv8Avz7rE4) by
> **Beatrice Ghorra** (*Tech By Bea*) — the same author as the upstream
> `beghorra/csw_blast_radius_demo` repo. The script in `docs/STORY.md`
> mirrors the on-screen beats (architecture diagram → lab walk → API-driven
> phases → before-enforcement probe wall → enforce → `nft list ruleset` on
> the VM → CSW Enforcement tab) so any SE can deliver the same demo.
>
> This fork generalizes the upstream code so anyone can drop in their own
> tenant, scopes, label values, and VMs without touching the source. To
> reproduce the video's screens 1:1, set `demo.application_label: DemoBRD`
> in your `config.yaml`.

---

## The story you tell

> The real security question isn't *"can someone get in?"* — it is
> *"what happens once they do?"*

Perimeter defense is not enough. Once an attacker has a foothold on a
single workload, they have unrestricted east-west access to probe every
sensitive system on the same segment — databases, caches, internal APIs,
admin interfaces. Without microsegmentation, the **blast radius** of a
single compromise is the entire VLAN.

This demo proves it live, in three beats:

1. **Before enforcement** — a compromised app VM probes the database VM on
   every interesting port (`5432`, `8080`, `6379`, `3306`, ...). They all
   succeed. East-west is wide open. The simulator shows a wall of green.
2. **You hit Enforce.** CSW pushes the policy down to the host firewall
   (`nftables`) on every workload — not a network choke point, the
   workload's own kernel.
3. **After enforcement** — only the one declared business path
   (`app → db` on TCP `5432`) survives. Every other lateral probe collapses
   to red. The blast radius shrinks from "the entire segment" to "one line
   of policy."

Customer sees the change on three screens at once: the simulator terminal,
the CSW Global Visualization Canvas, and the actual `nftables` rules CSW
wrote into each VM.

---

## What's in the box

```
csw_blast_radius_demo/
├── menu.py                       # Interactive control center
├── config.yaml.example           # Templated config (copy to config.yaml)
├── .env.example                  # Templated credentials (copy to .env)
├── requirements.txt              # Optional Python deps (PyYAML)
│
├── auth/
│   └── csw_client.py             # HMAC-SHA256 signing client + TLS toggle
│
├── phases/
│   ├── phase1_scope_labels.py    # Label upload + scope creation
│   ├── phase2_agent_deploy.py    # SSH agent installation
│   ├── phase3_workspace_policy.py# Workspace + absolute policies + analysis
│   ├── phase4_enforce.py         # Manual policy enforcement
│   └── phase5_teardown.py        # Environment cleanup
│
└── traffic/
    └── simulator.py              # External / internal / combined traffic view
```

---

## Prerequisites

| Item                     | Notes                                                                 |
| ------------------------ | --------------------------------------------------------------------- |
| Python 3.9+              | `python3 --version`                                                   |
| macOS or Linux           | `ssh` and `scp` must be on `PATH`                                     |
| Two Linux VMs            | Reachable over SSH from your laptop                                   |
| Cisco Secure Workload    | SaaS or on-prem cluster you can hit on `https://`                     |
| CSW API key + secret     | With `app_policy_management`, `user_data_upload`, `sensor_management` |
| CSW agent installer      | Tenant-specific `tetration_installer.sh` from the CSW UI              |
| SSH key                  | Authorized on both VMs (`authorized_keys`)                            |

The lab VMs need root via `sudo` (the agent installer requires it) and a
glibc-based Linux that the CSW Linux enforcement agent supports.

---

## One-time setup

### 1. Clone your fork

```bash
git clone https://github.com/<your-org>/csw_blast_radius_demo.git
cd csw_blast_radius_demo
```

### 2. Optional: install PyYAML

The project ships with a tiny built-in YAML parser, so this is optional.
If you have any kind of complex YAML in `config.yaml` (anchors, multi-line
strings, comments after values containing `#`), install PyYAML:

```bash
python3 -m pip install -r requirements.txt
```

### 3. Generate an SSH key for lab access

Use a dedicated key — never share your personal SSH key with lab VMs.

```bash
ssh-keygen -t ed25519 -C "csw-lab" -f ~/.ssh/csw_lab_key
ssh-copy-id -i ~/.ssh/csw_lab_key.pub <ssh_user>@<vm_ip>   # once per VM
```

On macOS, register it with the Keychain so the demo runs passwordlessly:

```bash
ssh-add --apple-use-keychain ~/.ssh/csw_lab_key
echo 'ssh-add --apple-use-keychain ~/.ssh/csw_lab_key 2>/dev/null' >> ~/.zshrc
```

On Linux:

```bash
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/csw_lab_key
```

### 4. Download the CSW agent installer

The installer embeds your tenant URL and a tenant-specific TLS certificate.

1. Log into your CSW UI
2. **Manage → Agents → Installer** tab
3. Pick **Agent Script Installer → Linux → Enforcement → No Expiration**
4. Save as `tetration_installer.sh` in the repo root

`.gitignore` already excludes this file so it never ends up on a public
branch.

### 5. Create your credentials file

```bash
cp .env.example .env
```

Then edit `.env`:

```dotenv
CSW_API_KEY=your_api_key_here
CSW_API_SECRET=your_api_secret_here
CSW_TENANT=your-cluster.tetrationcloud.com   # no scheme, no path

# Optional: turn off TLS verification for self-signed clusters
# or corporate TLS-inspection proxies. Default is on.
# CSW_VERIFY_SSL=false
```

Generate the API key in the CSW UI under
**Settings → API Keys → Create API Key** with these capabilities checked:

- `app_policy_management`
- `user_data_upload`
- `sensor_management`

### 6. Create your environment config

```bash
cp config.yaml.example config.yaml
```

Edit `config.yaml`. The fields you must fill in are:

```yaml
csw:
  tenant: "your-cluster.tetrationcloud.com"
  root_scope_name: "YOUR_ROOT_SCOPE"          # e.g. "Default" or your tenant root

ssh:
  key_path: "~/.ssh/csw_lab_key"
  user: "labuser"                             # default SSH user for VMs

vms:
  - ip: "10.0.0.11"
    hostname: "vm-app"
    role: "app"                               # the "compromised" attacker host
    env: "lab-demo"
    ssh_user: "labuser"                       # overrides ssh.user when set

  - ip: "10.0.0.12"
    hostname: "vm-db"
    role: "db"                                # the "crown jewel" target
    env: "lab-demo"
    ssh_user: "labuser"

demo:
  scope_name: "BlastRadiusLab"                # CSW child scope to create
  parent_scope_name: "YourParentScope"        # parent (often = root_scope_name)
  workspace_name: "Blast Radius Demo Policy"
  application_label: "BlastRadiusDemo"        # value of the Application label
                                              # used in the scope query
  allowed_port: 5432                          # the ONE business port app -> db
  mgmt_ip: "203.0.113.10"                     # YOUR laptop's outbound IP
  mgmt_port: 22                               # what your laptop is allowed on

agent_installer: "./tetration_installer.sh"
```

> **About `mgmt_ip`** — the management ALLOW rule lives in CSW and uses an
> IP-based filter (your laptop has no agent). Run `curl ifconfig.me` from
> your laptop and paste that address in. If your laptop's outbound IP
> changes regularly, plan to refresh it before each demo or use a stable
> jump host instead.

---

## Running the demo

```bash
python3 menu.py
```

You will see something like:

```
============================================================
  CSW Blast Radius Demo Builder
============================================================
  Tenant    : your-cluster.tetrationcloud.com
  Scope     : BlastRadiusLab
  Workspace : Blast Radius Demo Policy
  VMs       : 2 configured

  Phases
  ------------------------------------------------
  1  Create scope + upload labels to CSW
  2  Deploy agents to lab VMs (SSH)
  3  Create workspace + policy + start analysis
  4  ENFORCE  (live demo moment -- lock the doors)
  5  Teardown (clean up after demo)

  Utilities
  ------------------------------------------------
  TE  Traffic simulator -- External
  TI  Traffic simulator -- Internal
  TC  Traffic simulator -- Combined
  N   Show nftables rules on VMs
  S   Show environment status
  A   Auto prep -- run phases 1, 2, 3 in sequence (no enforce)
  Q   Quit
```

The smart play: hit **`S`** first to verify the environment looks healthy,
then **`A`** to run all the prep phases unattended. The enforcement moment
(option `4`) is the only thing you do while the customer is on the call.

### What each phase does

| Phase | What it does                                                                                                      | Idempotent?              |
| ----- | ----------------------------------------------------------------------------------------------------------------- | ------------------------ |
| 1     | Uploads `Application`, `role`, `hostname` labels to each VM IP, then creates a child scope with a label query     | Yes                      |
| 2     | SSHes into each VM, copies and runs the installer, polls the sensors API until each agent reports active          | Yes — skips installed VMs|
| 3     | Creates the workspace, defines `app→db`, `mgmt→app:22`, `mgmt→db:22` ALLOW + catch-all DENY, starts analysis      | Yes — reuses by name     |
| 4     | Reads `analyzed_version` and enforces it. Requires you to literally type `ENFORCE`                                | Yes                      |
| 5     | Disables enforcement, deletes inventory filters, deletes workspace, deletes scope. Optionally uninstalls agents   | Yes                      |

### The policy that gets installed

| Consumer        | Provider        | Port             | Action |
| --------------- | --------------- | ---------------- | ------ |
| app VM          | db VM           | TCP/`allowed_port` | ALLOW |
| management IP   | app VM          | TCP/`mgmt_port`  | ALLOW |
| management IP   | db VM           | TCP/`mgmt_port`  | ALLOW |
| everything else | everything else | any              | DENY   |

These are **absolute** policies (not learned by ADM). The lab is a green
field with no historical traffic, so we declare intent directly. The
management SSH rule has to be IP-based anyway — your laptop has no CSW
agent and ADM would never discover it.

---

## Demo day playbook

> See [`docs/STORY.md`](docs/STORY.md) for the full presenter script —
> the same beats as the companion video, with timestamps and exact lines
> to say at each transition.

### Night before

```bash
python3 menu.py
# A — runs phases 1, 2, 3 unattended
```

### Morning of (sanity check)

```bash
python3 menu.py
# S — confirm: agents active, scope exists, workspace exists, analysis ON
# N — capture the OPEN nftables state (screenshot for the before/after)
```

### Two terminals open when the customer joins

**Terminal 1 — the live evidence:**

```bash
python3 traffic/simulator.py --config config.yaml --mode combined
```

**Terminal 2 — the trigger:**

```bash
python3 menu.py
# Sit at the menu
```

**Browser:** CSW → *Defend → Segmentation* → your workspace → *Policy
Analysis*. Live escaped flows will already be appearing — that is the
"we can see the footprints, but the door is still open" moment.

### The moment

In Terminal 2:

```
Select: 4
Type ENFORCE
```

All three screens flip simultaneously. In the simulator the `app → db`
business port stays green, everything else turns red. In CSW, escaped
flows stop. On the VMs (`N` in the menu), `nftables` shows the rules
CSW just pushed.

### After

```bash
python3 menu.py
# N — show the enforced nftables state (the "what changed" proof)
# 5 — teardown
```

---

## Traffic simulator modes

Run any mode standalone, or trigger them from the menu (`TE`, `TI`, `TC`).

```bash
python3 traffic/simulator.py --mode external   # laptop -> VMs (perimeter view)
python3 traffic/simulator.py --mode internal   # vm-app -> vm-db (lateral view)
python3 traffic/simulator.py --mode combined   # both, alternating rounds
python3 traffic/simulator.py --mode nftables   # one-shot dump of host fw rules
```

| Mode      | Tells the story of...                                                              |
| --------- | ---------------------------------------------------------------------------------- |
| External  | An attacker outside the segment trying to reach VMs                                |
| Internal  | A workload **already inside** trying to pivot to the database — the real story    |
| Combined  | Both, rotating. This is the recommended live-demo view                             |
| NFTables  | One-shot proof: what CSW actually wrote to each host's firewall                    |

---

## Non-interactive usage

```bash
# Single phase
python3 menu.py --phase 1
python3 menu.py --phase 4

# Prep phases only (1 + 2 + 3) — never auto-enforces
python3 menu.py --phase all
```

---

## How CSW authentication works

`auth/csw_client.py` signs every request with HMAC-SHA256:

```
Timestamp     : YYYY-MM-DDTHH:MM:SS+0000
Body checksum : SHA256 hex of the body (empty string for GET/DELETE)
String to sign: METHOD\nPATH\nCHECKSUM\napplication/json\nTIMESTAMP\n
Signature     : base64( HMAC-SHA256(api_secret, string_to_sign) )
Headers       : Id, Authorization, Timestamp, Content-Type, X-Tetration-Cksum
```

Credentials are read **only** from environment variables (`CSW_API_KEY`,
`CSW_API_SECRET`, `CSW_TENANT`). Nothing is ever read from a file by the
client itself — the menu loads `.env` at startup.

`CSW_VERIFY_SSL=false` disables TLS verification for self-signed clusters
or corporate TLS-inspection proxies. Default is verification ON. Only
disable for ephemeral lab tenants and rotate API keys when you are done.

---

## Troubleshooting

| Symptom                                                | Fix                                                                                                                       |
| ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------- |
| `Config not found: .../config.yaml`                    | `cp config.yaml.example config.yaml` and edit                                                                             |
| `CSW_API_KEY not set`                                  | `cp .env.example .env`, fill in keys, retry                                                                               |
| `CERTIFICATE_VERIFY_FAILED`                            | Self-signed cluster or TLS-inspection proxy. Set `CSW_VERIFY_SSL=false` in `.env`                                          |
| `Permission denied (publickey)`                        | Run `ssh-add ~/.ssh/csw_lab_key` in the same shell. On macOS use `--apple-use-keychain`                                   |
| Phase 2 says "agent already installed" but no traffic  | Wait 60–120 seconds for the agent to register, then re-run `S`. Agents check in on a schedule                            |
| Phase 3 fails with `mgmt_ip is required`               | Add `demo.mgmt_ip` and `demo.mgmt_port` to `config.yaml`                                                                  |
| Phase 4 says "no analyzed version yet"                 | Analysis needs ~2 min after Phase 3 to produce its first version. Wait, then retry                                       |
| Internal traffic still works after enforce             | Confirm the agent is in **enforcement** mode in the CSW UI, not just installed. Re-run Phase 4                            |

---

## Security notes

- **No credentials in code or git.** Everything is in `.env`, which is
  ignored. The `tetration_installer.sh` is also git-ignored because it
  contains tenant-specific certificates.
- **TLS verification is on by default.** Only flip it off for lab tenants.
- **SSH options used by the deployer:** `StrictHostKeyChecking=no` and
  `UserKnownHostsFile=/dev/null` are intentional for short-lived lab VMs
  whose host keys rotate often. Do not use this code path against
  production hosts — replace those flags with proper known-hosts pinning.
- **Phase 4 is the only destructive moment.** It pushes firewall rules.
  Always require the literal `ENFORCE` confirmation that the menu enforces.

---

## License

Apache 2.0 (inherited from the upstream project).
