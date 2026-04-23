# Demo Storyline — Stop Lateral Movement with CSW

This is the presenter-facing script for the CSW Blast Radius demo. It mirrors
the beats in the companion video [Stop Lateral Movement: Blast Radius
Containment with Cisco Secure Workload](https://www.youtube.com/watch?v=_Dv8Avz7rE4)
by **Beatrice Ghorra** (Tech By Bea, April 2026) — the same author as the
upstream `beghorra/csw_blast_radius_demo` repo. Any SE can use this script
to deliver the same demo with the same narrative arc.

Each beat below maps to:
- a video timestamp,
- the exact menu/simulator action you take,
- the screen the customer should be watching,
- and the line you should be saying.

You do not have to read the lines verbatim — they are there so a new
presenter has scaffolding the first time through. After two or three runs
you will deliver them in your own voice.

> **To reproduce the video 1:1**, set `demo.application_label: DemoBRD`
> in your `config.yaml` — that is the literal label value Beatrice uses
> on screen. This fork makes it configurable so you can use your own
> customer-facing label name.

---

## Cast

| Role           | What it represents                             | In `config.yaml`        | Video example     |
| -------------- | ---------------------------------------------- | ----------------------- | ----------------- |
| `vm-app`       | A workload an attacker has already compromised | `vms[*].role: app`      | `demo-app` `10.1.42.11` |
| `vm-db`        | The crown-jewel database (Postgres on `5432`)  | `vms[*].role: db`       | `demo-db` `10.1.42.15`  |
| Mgmt host      | The "management console" with break-glass SSH  | `demo.mgmt_ip`          | Mac `10.8.243.17` |
| CSW UI         | What you keep open in a second monitor         | Defend → Segmentation   | —                 |

Both VMs in the video are **Ubuntu 22.04**, listening on `5432, 8080,
6379, 3306, 22`. Those are the same ports the bundled simulator probes:
`5432` (Postgres), `8080` (web admin), `6379` (Redis), `3306` (MySQL),
`22` (SSH). All of them are interesting to an attacker inside the
segment — none of them should be reachable from `vm-app` after
enforcement, except Postgres on `5432`.

---

## Beat 1 — Frame the problem with the architecture diagram  (video 0:08 → 0:22)

**Screen:** the architecture slide showing North/South vs East/West with
the bug icon on a compromised VM and arrows reaching across to bare-metal
servers, Kubernetes clusters, and other VMs.

**Say:**

> The question that matters is not *"can someone get into my network?"*
> Everyone has been asked that question for twenty years. The question
> that matters now is *"what happens after they do?"*
>
> Look at this diagram. Your perimeter — North/South — is what almost
> every security investment of the last decade has been about. But once
> something is inside that perimeter, it has East/West access to
> everything on the same segment. Bare-metal database servers, your
> Kubernetes cluster, every other VM. The blast radius of one
> compromised workload is the entire data center.

**Why this matters for CSW:** every other story in the deck (visibility,
ADM, policy intent) is a means to this end. Lead with the outcome.

---

## Beat 2 — Show the lab  (video 0:45)

**Screen:** the lab-environment slide, then the terminal — `python3
menu.py` and pick `S` (status).

**What the customer sees:** two **Ubuntu 22.04** workloads (`demo-app`
at `10.1.42.11`, `demo-db` at `10.1.42.15`) with `5432, 8080, 6379,
3306, 22` open on each. A management Mac (`10.8.243.17` in the video)
keeps SSH open from outside the scope.

**Say:**

> Two Ubuntu workloads. One is an application tier; one is a database
> tier with Postgres on `5432`. They both have other ports open — `8080`,
> `6379`, `3306` — because real workloads always do. Forgotten admin
> pages, an old Redis someone never decommissioned, a MySQL service the
> team migrated off but never shut down. This is what an attacker
> actually sees inside your network.
>
> The Mac up here is my management console. I get to keep SSH to both
> workloads even after enforcement, because if I lose access to my own
> lab in the middle of a customer demo, that is a different kind of
> blast radius.

---

## Beat 3 — Everything is API-driven  (video 1:24)

**Screen:** the slide listing the **4 demo phases** — Tagging, Agent
Deployment, Workspace + Policy, Enforce. (Phase 5 / teardown is in this
fork's `menu.py` but is not shown in the video — it runs after the
camera stops.)

**Say:**

> Everything you are about to see — the scope, the labels, the workspace,
> the policy, the enforcement — is driven by the Cisco Secure Workload
> REST API from a Python script. Nothing here uses the UI. That means
> the same flow you watch me run in the next four minutes drops directly
> into a CI/CD pipeline. Microsegmentation becomes part of how you
> deploy applications, not a separate ticket to a separate team.

This is the line that converts a "cool demo" into a "platform play."
Do not skip it.

---

## Beat 4 — Identity by labels, not IPs  (video 1:54)

**Screen:** menu, choose `1` (or, if you used `A` last night, just point
at the CSW UI → **Organize → Scopes and Inventory** — the same screen
the video flips to where the new tags appear instantly on each VM).

**What Phase 1 did:**
- Pushed inventory labels (`Application=DemoBRD` in the video — your
  `demo.application_label` value here, plus `role=app|db`,
  `hostname=<vm>`) to each workload IP via the user-data API.
- Created a child scope whose membership query is **only**
  `user_Application == <your label>`. There are zero IP addresses in
  that query.

**Say:**

> Notice what is not in this policy: IP addresses. Workloads belong to
> this scope because of *what they are*, not *where they sit*. If
> tomorrow my application gets a new IP, gets re-deployed in a different
> VPC, or scales horizontally to ten replicas, the policy follows the
> label. The policy is intent — the IP is plumbing.

---

## Beat 5 — Define the intent  (video 2:33)

**Screen:** menu, choose `3`. The video shows the script's terminal
output enumerating the rules as they are written, then flips to the
workspace in CSW UI → **Defend → Segmentation → Blast Radius Demo Policy**.

**What Phase 3 wrote:** three absolute ALLOWs and one catch-all DENY —
exactly the rules the video calls out on screen.

| Consumer        | Provider     | Port             | Action |
| --------------- | ------------ | ---------------- | ------ |
| `demo-app`      | `demo-db`    | TCP/`5432`       | ALLOW  |
| `mgmt-mac`      | `demo-app`   | TCP/`22`         | ALLOW  |
| `mgmt-mac`      | `demo-db`    | TCP/`22`         | ALLOW  |
| everything else | everything else | any           | **DENY** |

**Say:**

> Three rules. The application can talk to the database on `5432` —
> that is the business path. My management host can SSH to both, so I
> can keep doing my job. Everything else: explicit deny. Not "default
> deny because we forgot a rule" — explicit, written-down deny that
> shows up in the policy log.

Pause on the catch-all DENY. That is the line that does the work in
the next beat.

---

## Beat 6 — Prove lateral movement is open  (video 3:27)

**Screen:** Terminal 1, started before the call:

```bash
python3 traffic/simulator.py --mode combined
```

The simulator alternates two perspectives:

- **External** — your laptop probing `vm-db` directly (perimeter view)
- **Internal** — `vm-app` SSHing into itself and running `nc` against
  `vm-db` (the **lateral movement** view — this is the important one)

Right now, every internal probe comes back `[OPEN]`. Postgres, Redis,
MySQL, SSH, HTTP, the random web admin — all reachable from `vm-app`.

**Say (point at the green wall of Internal output):**

> This is what an attacker on `vm-app` sees today. They can hit Postgres,
> they can hit Redis, they can hit MySQL, they can hit the admin port on
> 8080. Anything they can reach, they can probe — and once they know
> the version and configuration, they can exploit. There is no policy
> stopping them, because everything inside this segment trusts everything
> else inside this segment.

---

## Beat 7 — The enforcement moment  (video 4:05)

**Screen:** Terminal 2 (the menu). Customer's eyes on Terminal 1.

```
Select: 4
Type ENFORCE
```

**What Phase 4 does:**
- Reads the workspace's `analyzed_version` (e.g. `p1`)
- Calls `enable_enforce` with `{"version": "p1"}`
- Polls until `enforcement_enabled == True`
- CSW pushes the policy down to the **host firewall** (`nftables`) on
  every workload — not a network choke point, the workload's own kernel.

**Say (while it propagates, ~10–20 seconds):**

> CSW is now writing rules into the OS firewall on each of those
> workloads. This is not a firewall in the network path — this is the
> kernel of the workload itself, deciding which packets it will accept.
> Even if the attacker fully owns this VM, they cannot turn this off
> without root and without setting off the alarms we will look at next.

---

## Beat 8 — Prove the blast radius collapsed  (video 4:36)

**Screen:** Terminal 1 — the simulator that has been running the whole time.

What the customer sees, **without you touching anything:**

- TCP `5432` (the business path) stays `[OPEN] CONNECTED`.
- SSH on TCP `22` from the Mac stays `[OPEN]` — your management
  carve-out is still valid.
- Every other lateral probe — `8080`, `6379`, `3306` — flips to
  `[BLOCK] TIMEOUT` (the agent is silently dropping the packets, not
  refusing them, which is what an attacker actually sees and is
  intentionally less useful to them than a clean RST).

**Say:**

> The compromised application can still do its job — it can still reach
> the database on `5432`, the business doesn't break. My management SSH
> path is still up because I declared that intent. But every other path
> the attacker had two minutes ago — Redis, MySQL, the random web admin
> on 8080 — is now timing out. Not refused, *timing out*: the host
> firewall is silently dropping the packets, so an attacker scanning
> this workload doesn't even get clean reconnaissance signal.
>
> The blast radius of a compromise on `demo-app` is now exactly one TCP
> port to one workload. That is what blast radius containment looks like.

---

## Beat 9 — Show the proof: the OS, then the dashboard  (video 5:24 → 6:00)

The customer has now seen the simulator do the thing. Close the loop in
exactly the order the video does — start at the OS to prove the rules
are real, then pull back to the CSW UI to prove this is auditable at
scale.

### 9a. The OS firewall — `sudo nft list ruleset` on the VM  (video 5:32)

In the menu, choose `N` to dump `nftables` from each VM. (The video
SSHes into the VM directly and runs `sudo nft list ruleset` — same
output, the menu just wraps the SSH for you.)

**What you see on screen:** the raw, complex `nftables` ruleset that
CSW generated and pushed into the kernel. ACCEPT for the allowed
business path, ACCEPT for the management SSH carve-out, DROP for
everything else.

**Say:**

> This is the actual rule, written into the kernel of `demo-db` by the
> CSW agent. Nobody hand-wrote this nftables ruleset — CSW generated
> it from the abstract policy I declared three minutes ago and pushed
> it down. If the agent process dies, these rules stay. If the kernel
> reboots, the agent reapplies them on the way up. There is no way to
> bypass this with an application-layer exploit, because the application
> never gets to see the packet.

### 9b. The Enforcement tab — green Permitted, red Rejected  (video 6:00)

Switch to CSW UI → **Defend → Segmentation → Blast Radius Demo Policy →
Enforcement** tab. The line graph plots flows over time, green for
**Permitted** and red for **Rejected**.

Drop the consumer and provider filters in the side panel to drill into
the exact connection attempts that were blocked while the simulator was
running.

**Say:**

> Every probe my simulator just ran is here. Permitted flows in green,
> rejected flows in red, plotted over time so you can see the moment
> enforcement turned on. I can filter by consumer or provider — let me
> pull up `demo-app` as the consumer — and now I can see every single
> port it tried to reach on `demo-db` and the policy decision for each
> one. This is what goes to your SOC. This is what goes to your
> auditors. This is the evidence that microsegmentation is doing the
> thing you said it would do, on the workloads you said it would do it
> on.

### 9c. (Optional, off-camera) The workload identity card

If you have time and the customer is engaged: CSW UI → Organize →
Scopes and Inventory → click `demo-db` → **Concrete Policies** tab.
Show the labels and the rules CSW computed for this specific workload
from the abstract policy. The video does not show this view, but it is
the strongest answer to "what happens when I add a second database
tomorrow?"

---

## Beat 10 — Tear down  (off-camera)

After the demo, in the menu:

```
Select: 5
Also uninstall agents from VMs? [y/N]: n   (usually — keeps next demo fast)
```

This disables enforcement, deletes the three filters, the workspace, and
the scope, in dependency order. The lab is back to a clean slate for the
next run.

---

## Common follow-up questions (and how to answer them)

| Customer asks                                            | Answer in one breath                                                                                                                                |
| -------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| "What if the agent gets killed?"                         | The rules persist in `nftables`. The agent is what *writes* them; once written, they stay. Killing the agent does not unlock the workload.          |
| "What if I write a bad policy?"                          | That is what Policy Analysis (Beat 9c) is for. You run it for hours or days **before** you enforce. Escaped flows mean "you forgot a rule."         |
| "What about scale?"                                      | This is exactly the same flow with 5 workloads or 5,000. The policy is by label; the workloads are populated by the label query.                    |
| "Can this be in our pipeline?"                           | Already is — everything you saw is the REST API from a Python script. Drop the same calls into Jenkins, Argo, GitHub Actions, anywhere.             |
| "What if my IP changes?"                                 | The label-based policy doesn't care. The mgmt-IP carve-out for SSH does — but in a real deployment that is a stable jump host, not a roaming laptop.|
| "Do I have to enforce immediately?"                      | No. Run analysis-only for as long as you need (days, weeks). Enforcement is a deliberate, separate action.                                          |

---

## Calibration notes for new presenters

- **Run the prep phases the night before.** Phase 2 (agent install) can
  take 60–90 seconds per VM. Doing this live wastes the customer's time
  and hides the actual story.
- **Have the simulator already running** when you get on the call. The
  visible "wall of green" before enforcement is most of the impact. If
  you start the simulator after framing the problem, the audience has
  to context-switch and the moment lands flat.
- **Resist the urge to narrate every line of script output.** Let the
  red wall in Beat 8 land in silence for two or three seconds. The
  customer will say something. Whatever they say is your next line.
- **Never demo without Beat 9.** A simulator turning green-to-red is a
  cool magic trick. The host firewall, identity card, and policy log
  are what makes it credible.
