"""Rule-based detection + correlation. Every verdict carries plain-English reasoning
and the IDs of the events that triggered it. Nothing here is a confirmed attack verdict."""
import ipaddress
import json
import re

import pandas as pd

TACTIC_ORDER = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
                "Credential Access", "Discovery", "Collection", "Exfiltration"]
GENERIC_ENTITIES = {"", "-", "root", "admin", "system", "www-data", "unknown", "nobody", "local service"}


def is_internal(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in ipaddress.ip_network(n) for n in
               ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"))


def to_int(v):
    try:
        return int(float(str(v).replace(",", "")))
    except ValueError:
        return 0


def size_bytes(text):
    m = re.search(r"(\d+(?:\.\d+)?)\s*(KB|MB|GB)\b", text, re.I)
    if not m:
        return 0
    return float(m.group(1)) * {"kb": 1e3, "mb": 1e6, "gb": 1e9}[m.group(2).lower()]


def human(n):
    for unit, d in (("GB", 1e9), ("MB", 1e6), ("KB", 1e3)):
        if n >= d:
            return f"{n / d:.1f} {unit}"
    return f"{int(n)} B"


# Each rule returns None or (action, event_type, tactic, severity 1-3, reason)
def evaluate(row, f):
    """row: normalized dict, f: raw fields dict. Returns list of rule hits."""
    blob = " ".join([row["action"], row["details"], " ".join(f"{k}={v}" for k, v in f.items())]).lower()
    fmt = f.get("format", "")
    hits = []

    def hit(action, etype, tactic, sev, reason):
        hits.append((action, etype, tactic, sev, reason))

    ip, user, host = row["source_ip"], row["user"], row["host"]

    # --- authentication -------------------------------------------------------
    if re.search(r"failed password|authentication failure|logon failure|eventid=4625|login_failed|login failed|invalid password", blob):
        who = f"invalid user '{user}'" if f.get("invalid_user") else f"account '{user or 'unknown'}'"
        hit("login_failed", "authentication", "Credential Access", 1,
            f"Failed login for {who}" + (f" from {ip}" if ip else "") + ". A single failure is common, but several in a row can indicate password guessing.")
    if re.search(r"accepted (password|publickey)|eventid=4624|login_success|successful login|logon success", blob):
        if user.lower() == "root" and ip and not is_internal(ip):
            hit("login_success", "authentication", "Initial Access", 3,
                f"Direct root login succeeded from external address {ip}. Root logins from the internet are rarely legitimate.")
        elif ip and not is_internal(ip):
            hit("login_success", "authentication", "Initial Access", 1, f"Successful login for '{user}' from external address {ip}.")
        else:
            hit("login_success", "authentication", "", 0, f"Successful login for '{user}'.")

    # --- credential / sensitive file access ---------------------------------
    if fmt != "web" and re.search(r"/etc/shadow|/etc/sudoers|ntds\.dit|\bsam\b.*hive|lsass|mimikatz|credential dump|sekurlsa", blob):
        hit("credential_access", "authentication", "Credential Access", 3,
            f"Sensitive credential store accessed ({f.get('command') or row['details'][:80]}). This file holds password hashes or secrets.")
    if re.search(r"sensitive_file_access|sensitive file|payroll_export", blob) and "dlp" not in blob:
        hit("sensitive_file_access", "file_access", "Collection", 2, "A file with a sensitive-sounding name was accessed.")

    # --- identity -------------------------------------------------------------
    if re.search(r"mfa_disabled|mfa disabled|disable[ds]?.{0,20}(mfa|multi-?factor)|2fa disabled", blob):
        tgt = f.get("target_user")
        hit("mfa_disabled", "identity", "Defense Evasion", 3,
            f"Multi-factor authentication was turned off" + (f" for '{tgt}'" if tgt else "") + (f" by '{user}'" if user else "") +
            (f" from {ip}" if ip else "") + ". Removing MFA weakens an account and is a common step before account takeover.")
    if re.search(r"eventid=4720|user account was created|account created|useradd", blob):
        tgt = f.get("targetusername") or f.get("target_user") or "a new account"
        sev = 3 if re.search(r"admin|backup|svc|root", tgt.lower()) else 2
        hit("account_created", "identity", "Persistence", sev,
            f"'{user or 'an account'}' created '{tgt}'" + (f" on {host}" if host else "") + ". Newly created privileged-looking accounts can be used to keep access.")
    if re.search(r"eventid=4672|special privileges assigned|sedebugprivilege|sebackupprivilege|serestoreprivilege|setakeownership", blob):
        privs = f.get("privilegelist", "")
        hit("privilege_assigned", "identity", "Privilege Escalation", 3 if "debug" in blob else 2,
            f"Special privileges assigned to '{user}'" + (f" ({privs})" if privs else "") + ". Debug/backup/restore rights allow reading protected data and memory.")

    # --- file integrity -------------------------------------------------------
    path = f.get("path", "")
    ev = (f.get("event_type", "") or "").lower()
    if "file_modify" in ev or "file_delete" in ev or "file_create" in ev:
        if re.search(r"\.(php|aspx?|jsp|cgi)$", path.lower()) or "/www/" in path.lower():
            risky = f.get("permission") in ("0777", "777") or f.get("owner_changed", "").lower() == "true"
            hit("web_content_modified", "file", "Persistence", 3 if risky else 2,
                f"Web-served file {path} was modified by '{user}'" +
                (" and left world-writable / ownership changed" if risky else "") +
                ". Altered login pages are a common way to plant a backdoor or capture credentials.")
        if "file_delete" in ev and re.search(r"/var/log|\.log$|eventlog|audit", path.lower()):
            hit("log_deleted", "file", "Defense Evasion", 3,
                f"Log file {path} was deleted by '{user}'. Removing logs is a typical attempt to hide earlier activity.")

    # --- network / firewall / web ------------------------------------------
    dst = f.get("dst", "")
    verdict = f.get("verdict", "")
    if fmt == "firewall":
        if verdict == "deny" and ip and not is_internal(ip) and f.get("dpt") in ("3389", "22", "445", "5985", "23"):
            hit("blocked_inbound_attempt", "network", "Initial Access", 1,
                f"Firewall blocked an inbound connection from external {ip} to {dst}:{f.get('dpt')} (rule {f.get('rule', 'n/a')}). Shows the host was being probed.")
        out = to_int(f.get("bytes_out"))
        if verdict == "allow" and out >= 10_000_000 and is_internal(ip) and dst and not is_internal(dst):
            hit("outbound_transfer", "network", "Exfiltration", 3 if out >= 50_000_000 else 2,
                f"{ip} sent {human(out)} to external address {dst}. Large outbound volume to an unfamiliar destination can indicate data leaving the network.")
    if fmt == "web":
        p = f.get("path", "")
        if re.search(r"\.\./|%2e%2e|etc/passwd|union\s+select|<script|cmd\.exe|/bin/sh", p.lower()):
            hit("web_attack", "web", "Initial Access", 2,
                f"Request from {ip} contains a path-traversal/exploit pattern ({p[:60]}). Indicates scanning or an attempt to read server files.")
        size = to_int(f.get("bytes"))
        if f.get("method") == "POST" and re.search(r"export|download|dump|backup", p.lower()) and f.get("status", "").startswith("2") and size >= 500_000:
            hit("bulk_data_export", "web", "Collection", 2 if size < 50_000_000 else 3,
                f"{ip} pulled a {human(size)} response from {p.split('?')[0]} (HTTP {f.get('status')}). A large export through an admin endpoint may be bulk data collection.")
    if re.search(r"outbound_transfer|exfil|upload", blob) and fmt not in ("firewall", "web") and "dlp" not in blob:
        sz = size_bytes(row["details"])
        if sz >= 10e6 or "unusual" in blob:
            hit("outbound_transfer", "network", "Exfiltration", 3 if sz >= 50e6 else 2,
                f"Outbound transfer recorded ({human(sz) if sz else 'size not stated'}). Compare with normal traffic for this host.")

    # --- process execution ----------------------------------------------------
    if re.search(r"-enc\b|-encodedcommand|encodedcommand|powershell_encoded|encoded command", blob):
        parent = f.get("parent_process", "")
        office = re.search(r"winword|excel|outlook|powerpnt", parent.lower())
        hit("powershell_encoded_command", "process", "Execution", 3 if office or "suspicious" in blob else 2,
            "PowerShell ran an encoded (obfuscated) command" + (f" launched by {parent}" if parent else "") +
            (f" on {host}" if host else "") + ". Office applications spawning PowerShell is a classic malicious-document pattern.")
    if re.search(r"rundll32", blob) and re.search(r"\\temp\\|appdata|/tmp/|\.dll", blob):
        hit("suspicious_dll_execution", "process", "Defense Evasion", 3 if re.search(r"temp|appdata", blob) else 2,
            "rundll32 loaded a DLL from a user-writable location" + (f" on {host}" if host else "") +
            (f" (verdict: {f['verdict']})" if f.get("verdict") else "") + ". Attackers use rundll32 to run payloads while blending in with system tools.")

    # --- database / DLP -------------------------------------------------------
    rows = to_int(f.get("rowsreturned") or f.get("rows_returned") or f.get("rows"))
    if rows >= 10_000 and (f.get("action", "").lower() == "select" or "select" in blob):
        hit("bulk_data_query", "database", "Collection", 3 if rows >= 100_000 else 2,
            f"'{user}' read {rows:,} rows from {f.get('object', 'a table')} in {f.get('database', 'a database')}. Unusually large reads of sensitive tables can be data collection ahead of theft.")
    if re.search(r"policy=.*(external transfer|exfil)|transfer_blocked|dlp_alert", blob):
        sz = f.get("size", "")
        hit("dlp_alert", "dlp", "Exfiltration", 3,
            f"DLP flagged '{user}' on {host} for an external transfer of {f.get('file', 'a file')} ({sz}) to {f.get('destination', 'an external site')}; action: {f.get('action', 'n/a')}. Even a blocked attempt shows intent to move confidential data.")

    # --- persistence ----------------------------------------------------------
    if re.search(r"cron|systemd|schtasks|scheduled task|execstart", blob) and re.search(r"/tmp/|/dev/shm|\.cache/|appdata|suspicious", blob):
        hit("persistence_scheduled_task", "system", "Persistence", 3,
            "A scheduled job / service was set to run a program from a temporary or hidden location" +
            (f" on {host}" if host else "") + ". Legitimate software rarely runs from /tmp or hidden cache folders.")

    # --- source-provided severity (only if nothing else matched) ---------------
    if not any(h[3] >= 2 for h in hits) and (f.get("risk", "").lower() in ("high", "critical") or f.get("severity", "").lower() in ("high", "critical")):
        hit(row["action"] or "source_flagged_high_risk", "alert", "", 2, "The source system itself rated this event high risk.")
    return hits


def enrich(df):
    """Add severity, tactic, tags (JSON list), why. Normalizes action/event_type."""
    sev, tactic, why, tags, actions, etypes = [], [], [], [], [], []
    for _, r in df.iterrows():
        try:
            f = json.loads(r["raw"]) if r.get("raw") else {}
        except (TypeError, ValueError):
            f = {}
        hits = evaluate(r, f)
        if hits:
            hits.sort(key=lambda h: -h[3])
            top = hits[0]
            sev.append(max(h[3] for h in hits))
            tactic.append(top[2])
            why.append(" ".join(dict.fromkeys(h[4] for h in hits if h[3] >= 1)) or top[4])
            tags.append(sorted({h[0] for h in hits}))
            actions.append(top[0])
            etypes.append(top[1])
        else:
            sev.append(0); tactic.append(""); why.append(""); tags.append([])
            actions.append(r["action"] or "log_entry")
            etypes.append(r["event_type"] or (f.get("format") or "log"))
    out = df.copy()
    out["severity"], out["tactic"], out["why"], out["tags"] = sev, tactic, why, tags
    out["action"], out["event_type"] = actions, etypes
    return out


# ---------------------------------------------------------------- correlation
def entities(row):
    try:
        f = json.loads(row["raw"]) if row["raw"] else {}
    except (TypeError, ValueError):
        f = {}
    ents = set()
    for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", " ".join(str(v) for v in f.values()) + " " + row["details"]):
        ents.add("ip:" + ip)
    for k in ("host", "computer", "hostname", "endpoint", "database"):
        if f.get(k):
            ents.add("host:" + f[k].lower().split(".")[0])
    if row["host"]:
        ents.add("host:" + row["host"].lower().split(".")[0])
    for k in ("user", "actor", "subjectusername", "targetusername", "target_user", "username"):
        v = (f.get(k) or "").lower()
        if v and v not in GENERIC_ENTITIES:
            ents.add("user:" + v)
    if row["user"] and row["user"].lower() not in GENERIC_ENTITIES:
        ents.add("user:" + row["user"].lower())
    for k in ("file", "path", "object"):
        v = f.get(k, "")
        if v:
            ents.add("file:" + v.lower().split("/")[-1])
    return ents


def fmt_t(ts):
    return ts.strftime("%H:%M:%S")


def analyze(df):
    """df must be enriched. Returns findings list (with evidence ids) and narrative steps."""
    findings = []
    if df.empty:
        return findings, []

    # 1) repeated failures -> success from the same source
    failed = df[df["tags"].apply(lambda t: "login_failed" in t)]
    for ip, grp in failed.groupby("source_ip"):
        if ip and len(grp) >= 3:
            later = df[(df["source_ip"] == ip) & df["tags"].apply(lambda t: "login_success" in t)]
            later = later[later["timestamp"] >= grp["timestamp"].min()]
            if not later.empty:
                s = later.iloc[0]
                before = grp[grp["timestamp"] <= s["timestamp"]]
                if len(before) >= 3:
                    findings.append({"level": "high", "tactic": "Credential Access", "title": "Repeated failures followed by a successful login",
                        "plain": f"{len(before)} failed login attempts from {ip} were recorded before a successful login for {s['user'] or 'an account'}.",
                        "why": "This sequence can be consistent with password guessing, but it does not prove that the account was compromised.",
                        "events": before["event_id"].tolist() + [s["event_id"]],
                        "start": before.iloc[0]["timestamp"].isoformat(), "end": s["timestamp"].isoformat()})
            else:
                findings.append({"level": "medium", "tactic": "Credential Access", "title": "Repeated failed logins",
                    "plain": f"{len(grp)} failed login attempts came from {ip}.",
                    "why": "Repeated failures can indicate password guessing or a misconfigured client. No success followed in the loaded logs.",
                    "events": grp["event_id"].tolist(), "start": grp.iloc[0]["timestamp"].isoformat(), "end": grp.iloc[-1]["timestamp"].isoformat()})

    # 2) one finding per high/medium-severity event, with the reasoning attached
    for _, r in df[df["severity"] >= 2].iterrows():
        findings.append({"level": "high" if r["severity"] >= 3 else "medium", "tactic": r["tactic"],
            "title": r["action"].replace("_", " ").capitalize() + (f" · {r['tactic']}" if r["tactic"] else ""),
            "plain": r["why"], "why": "Matched a detection rule on the fields of this record. Rules look for patterns that are often malicious but can have legitimate explanations; verify with the account owner or system owner.",
            "events": [r["event_id"]], "start": r["timestamp"].isoformat(), "end": r["timestamp"].isoformat()})

    # 3) sensitive access followed by outbound transfer (same user/host/ip)
    sens = df[df["tags"].apply(lambda t: bool({"sensitive_file_access", "bulk_data_query", "bulk_data_export"} & set(t)))]
    outb = df[df["tags"].apply(lambda t: bool({"outbound_transfer", "dlp_alert"} & set(t)))]
    for _, s in sens.iterrows():
        se = entities(s)
        for _, o in outb.iterrows():
            gap = (o["timestamp"] - s["timestamp"]).total_seconds()
            if 0 <= gap <= 3600 and (se & entities(o)):
                findings.append({"level": "high", "tactic": "Exfiltration", "title": "Data access followed by outbound transfer",
                    "plain": f"{s['action'].replace('_', ' ')} at {fmt_t(s['timestamp'])} was followed {int(gap // 60)} min later by {o['action'].replace('_', ' ')}, involving the same {', '.join(sorted(x.split(':')[1] for x in se & entities(o)))}.",
                    "why": "Access to sensitive data followed shortly by outbound transfer from the same entity may warrant investigation, but the logs alone do not establish that data was stolen.",
                    "events": [s["event_id"], o["event_id"]], "start": s["timestamp"].isoformat(), "end": o["timestamp"].isoformat()})
                break

    # 4) linked activity: flagged events sharing an entity within 60 min
    flagged = df[df["severity"] >= 1].reset_index(drop=True)
    ents = [entities(r) for _, r in flagged.iterrows()]
    parent = list(range(len(flagged)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    for i in range(len(flagged)):
        for j in range(i + 1, len(flagged)):
            shared = {e for e in (ents[i] & ents[j]) if not e.startswith("file:") or True}
            if shared and abs((flagged.at[j, "timestamp"] - flagged.at[i, "timestamp"]).total_seconds()) <= 3600:
                parent[find(i)] = find(j)
    groups = {}
    for i in range(len(flagged)):
        groups.setdefault(find(i), []).append(i)
    for idxs in groups.values():
        sub = flagged.loc[idxs]
        if len(sub) >= 2 and sub["severity"].max() >= 2 and sub["tactic"].replace("", pd.NA).dropna().nunique() >= 2:
            shared = set.intersection(*[ents[i] for i in idxs]) if len(idxs) > 1 else set()
            common = sorted(shared) or sorted({e for e in ents[idxs[0]] if sum(e in ents[i] for i in idxs) >= 2})[:3]
            names = ", ".join(c.split(":", 1)[1] for c in common[:3])
            phases = list(dict.fromkeys(sub.sort_values("timestamp")["tactic"].replace("", pd.NA).dropna()))
            findings.append({"level": "high" if sub["severity"].max() >= 3 else "medium", "tactic": phases[0] if phases else "",
                "title": "Linked activity" + (f" around {names}" if names else ""),
                "plain": f"{len(sub)} flagged events share common entities ({names or 'related hosts/accounts'}) within an hour: " + " → ".join(phases) + ".",
                "why": "Events that involve the same account, host or address in close succession are more meaningful together than alone. Entity links are drawn from the log fields, so check each event before concluding they are one incident.",
                "events": sub.sort_values("timestamp")["event_id"].tolist(),
                "start": sub["timestamp"].min().isoformat(), "end": sub["timestamp"].max().isoformat()})

    # 5) campaign: time-ordered chain of notable events spanning several tactics
    notable = df[df["severity"] >= 2].sort_values("timestamp")
    chains, cur = [], []
    for _, r in notable.iterrows():
        if cur and (r["timestamp"] - cur[-1]["timestamp"]).total_seconds() > 900:
            chains.append(cur); cur = []
        cur.append(r)
    if cur:
        chains.append(cur)
    for ch in chains:
        phases = list(dict.fromkeys(r["tactic"] for r in ch if r["tactic"]))
        if len(ch) >= 3 and len(phases) >= 3:
            hosts = sorted({r["host"].split(".")[0] for r in ch if r["host"]})
            findings.append({"level": "high", "tactic": "Multi-stage", "title": "Probable multi-stage incident",
                "plain": f"{len(ch)} notable events between {fmt_t(ch[0]['timestamp'])} and {fmt_t(ch[-1]['timestamp'])} progress through {len(phases)} attack phases ({' → '.join(phases)}) across {len(hosts)} system(s).",
                "why": "No single event proves an attack, but this many suspicious events in quick succession, covering access, persistence, collection and data movement, fits the shape of one coordinated intrusion. This is based on timing and attack-phase ordering, not on proof that the systems are connected. Verify each step.",
                "events": [r["event_id"] for r in ch], "start": ch[0]["timestamp"].isoformat(), "end": ch[-1]["timestamp"].isoformat()})

    # de-duplicate identical evidence sets, order: level then time
    seen, uniq = set(), []
    for f in findings:
        key = (f["title"], tuple(f["events"]))
        if key not in seen:
            seen.add(key); uniq.append(f)
    order = {"high": 0, "medium": 1, "low": 2}
    uniq.sort(key=lambda x: (0 if x["tactic"] == "Multi-stage" else 1, order.get(x["level"], 3), x["start"]))

    # narrative: every flagged event, in time order, grouped when consecutive in the same phase
    steps = []
    for _, r in df[df["severity"] >= 2].sort_values("timestamp").iterrows():
        steps.append({"time": r["timestamp"].strftime("%Y-%m-%d %H:%M:%S"), "tactic": r["tactic"] or "Alert", "text": r["why"],
                      "events": [r["event_id"]], "level": "high" if r["severity"] >= 3 else "medium"})
    return uniq, steps
