"""
Drishti — Windows Security Event synthetic generator
=====================================================
This is the "tap": run this script → events flow into raw.windows-events.
Ctrl+C → events stop.

Produces realistic Windows Security Audit events in the format that
a Vector windows_event_log source would forward. When you later install
a real Vector agent on your Windows box, the normalizer handles both
interchangeably — same fields, same topic.

Supported scenarios
  normal        steady mix of 4624/4625 logon events (~80% success)
  brute_force   bursts of 4625 failures from one external IP, then 4624
  new_account   periodic 4720 user account creation events
  mixed         randomly interleaves all three (default)

Usage
  uv run python scripts/generate_windows_events.py
  uv run python scripts/generate_windows_events.py --scenario brute_force
  uv run python scripts/generate_windows_events.py --scenario new_account --rate 0.5
  uv run python scripts/generate_windows_events.py --tenant kroger --rate 2

References
  Windows Security Audit Events (field-by-field):
    https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-logon
    https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624
    https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625
    https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720
  NtStatus codes for Status/SubStatus fields:
    https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55
  OCSF Authentication class (our target schema):
    https://schema.ocsf.io/classes/authentication
  Confluent Kafka Python producer:
    https://docs.confluent.io/kafka-clients/python/current/overview.html#producer
"""

import argparse
import json
import random
import sys
import time
from datetime import datetime, timezone

from confluent_kafka import Producer

# ── Config ────────────────────────────────────────────────────────────────────
BOOTSTRAP_SERVERS = "192.168.1.176:19092"
OUTPUT_TOPIC = "raw.windows-events"

# ── Realistic data pools ──────────────────────────────────────────────────────
USERS = [
    "jsmith", "mjohnson", "alee", "rbrown", "cwilson",
    "mgarcia", "jdavis", "kthomas", "swilliams", "pwang",
]
# Privileged accounts that attackers typically target
HIGH_VALUE_ACCOUNTS = ["administrator", "admin", "svc_sql", "svc_backup"]

WORKSTATIONS = [
    "CORP-WS001", "CORP-WS002", "CORP-LT003",
    "CORP-LT004", "CORP-SRV01", "CORP-SRV02",
]
DOMAIN = "CORP"
DC_HOST = f"CORP-DC01.{DOMAIN.lower()}.internal"

INTERNAL_IPS = [
    "10.0.1.10", "10.0.1.11", "10.0.1.45", "10.0.2.5",
    "10.0.2.22", "10.0.3.8", "172.16.0.15", "172.16.1.20",
]

# NtStatus codes — these appear in the Status and SubStatus fields of 4625 events.
# They tell analysts WHY the logon failed. Your normalizer maps these to outcome.
STATUS_SUCCESS = "0x0"
STATUS_LOGON_FAILURE = "0xC000006D"   # generic: wrong credentials, account disabled, etc.
STATUS_USER_NOT_FOUND = "0xC0000064"  # no such username in the domain
STATUS_WRONG_PASSWORD = "0xC000006A"  # username exists but password is wrong
STATUS_ACCOUNT_LOCKED = "0xC0000234"  # account is locked out

# LogonType values for 4624/4625
# https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624#logon-types
LOGON_TYPE_INTERACTIVE = "2"    # physical console or local login
LOGON_TYPE_NETWORK = "3"        # SMB share, scheduled task, WMI, etc.
LOGON_TYPE_REMOTE_INTERACTIVE = "10"  # RDP


# ── Event builders ────────────────────────────────────────────────────────────

def _base(event_id: int, computer: str, tenant_id: str) -> dict:
    """Fields common to all Windows Security Audit events."""
    return {
        "tenant_id": tenant_id,
        "EventID": event_id,
        "TimeCreated": datetime.now(timezone.utc).isoformat(),
        "Channel": "Security",
        "Computer": computer,
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "ProviderGuid": "{54849625-5478-4994-A5BA-3E3B0328C30D}",
    }


def make_4624(user: str, ip: str, computer: str, tenant_id: str,
              logon_type: str = LOGON_TYPE_NETWORK) -> dict:
    """
    EventID 4624 — An account was successfully logged on.

    Key fields for detection:
      TargetUserName   who logged on
      IpAddress        source of the logon request
      LogonType        how they logged on (network vs interactive vs RDP)
      Status           always 0x0 on success

    Common detection use: after-hours logins, logins from unusual IPs,
    logon after a burst of 4625 failures (brute force success).
    """
    e = _base(4624, computer, tenant_id)
    e.update({
        "Keywords": "Audit Success",
        "SubjectUserSid": "S-1-5-18",
        "SubjectUserName": "SYSTEM",
        "SubjectDomainName": "NT AUTHORITY",
        "TargetUserName": user,
        "TargetDomainName": DOMAIN,
        "TargetUserSid": f"S-1-5-21-1234567890-987654321-111111111-{random.randint(1000, 9999)}",
        "LogonType": logon_type,
        "WorkstationName": random.choice(WORKSTATIONS),
        "IpAddress": ip,
        "IpPort": str(random.randint(49152, 65535)),
        "Status": STATUS_SUCCESS,
        "SubStatus": STATUS_SUCCESS,
        "LogonProcessName": "Kerberos",
        "AuthenticationPackageName": "Kerberos",
        "KeyLength": "0",
    })
    return e


def make_4625(user: str, ip: str, computer: str, tenant_id: str,
              status: str = STATUS_WRONG_PASSWORD,
              logon_type: str = LOGON_TYPE_NETWORK) -> dict:
    """
    EventID 4625 — An account failed to log on.

    Key fields for detection:
      TargetUserName   who was targeted
      IpAddress        source of the failed attempt
      Status           WHY it failed (see NtStatus codes above)
      SubStatus        more specific reason

    Brute force pattern: many 4625s in short time from same IpAddress.
    Password spray pattern: one 4625 per user across many users from same IP.
    """
    e = _base(4625, computer, tenant_id)
    e.update({
        "Keywords": "Audit Failure",
        "SubjectUserSid": "S-1-5-18",
        "SubjectUserName": "SYSTEM",
        "SubjectDomainName": "NT AUTHORITY",
        "TargetUserSid": "S-1-0-0",   # null SID — logon not established
        "TargetUserName": user,
        "TargetDomainName": DOMAIN,
        "LogonType": logon_type,
        "WorkstationName": "-",
        "IpAddress": ip,
        "IpPort": str(random.randint(49152, 65535)),
        "Status": STATUS_LOGON_FAILURE,
        "SubStatus": status,
        "LogonProcessName": "NtLmSsp",
        "AuthenticationPackageName": "NTLM",
        "KeyLength": "128",
    })
    return e


def make_4720(new_user: str, actor: str, computer: str, tenant_id: str) -> dict:
    """
    EventID 4720 — A user account was created.

    Key fields for detection:
      SubjectUserName  who created the account (the actor)
      TargetUserName   the new account name
      TargetSid        SID assigned to new account

    Detection use: adversaries create backdoor accounts after gaining access.
    Alert on any account creation outside of provisioning windows.

    Reference:
      https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720
    """
    e = _base(4720, computer, tenant_id)
    e.update({
        "Keywords": "Audit Success",
        "SubjectUserName": actor,
        "SubjectDomainName": DOMAIN,
        "SubjectUserSid": f"S-1-5-21-1234567890-987654321-111111111-{random.randint(500, 999)}",
        "TargetUserName": new_user,
        "TargetDomainName": DOMAIN,
        "TargetSid": f"S-1-5-21-1234567890-987654321-111111111-{random.randint(1100, 9999)}",
        "SamAccountName": new_user,
        "DisplayName": new_user.replace("_", " ").title(),
        "UserPrincipalName": f"{new_user}@{DOMAIN.lower()}.internal",
        "PrimaryGroupId": "513",        # Domain Users RID
        "NewUacValue": "0x15",          # normal account, disabled, password not required
        "UserAccountControl": "%%2080 %%2082 %%2084",
    })
    return e


# ── Producer helper ───────────────────────────────────────────────────────────

def _send(producer: Producer, event: dict) -> None:
    """Serialize and produce one event. Key is the Computer field."""
    producer.produce(
        topic=OUTPUT_TOPIC,
        key=event.get("Computer", "unknown").encode("utf-8"),
        value=json.dumps(event).encode("utf-8"),
    )
    producer.poll(0)

    eid = event["EventID"]
    user = event.get("TargetUserName") or event.get("SubjectUserName", "?")
    ip = event.get("IpAddress", "-")
    ts = event.get("TimeCreated", "")[:19]
    print(f"  {ts}  EventID={eid:<5}  user={user:<20}  src={ip:<18}  tenant={event.get('tenant_id', '?')}")


def _random_external_ip() -> str:
    """Generate a plausible external IP (avoids RFC1918 and reserved ranges)."""
    while True:
        a = random.randint(1, 223)
        if a in (10, 127, 169, 172, 192):
            continue
        return f"{a}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


# ── Scenarios ─────────────────────────────────────────────────────────────────

def run_normal(producer: Producer, tenant_id: str, rate: float) -> None:
    """
    Steady background traffic: ~80% successful logons, ~20% failures.
    Internal IPs only. Realistic office-hours traffic.
    """
    print(f"[normal] Steady auth traffic — {rate:.1f} evt/s — Ctrl+C to stop")
    print()
    while True:
        user = random.choice(USERS)
        ip = random.choice(INTERNAL_IPS)
        computer = random.choice(WORKSTATIONS)

        if random.random() < 0.80:
            logon_type = random.choice([LOGON_TYPE_NETWORK, LOGON_TYPE_INTERACTIVE])
            event = make_4624(user, ip, computer, tenant_id, logon_type)
        else:
            event = make_4625(user, ip, computer, tenant_id)

        _send(producer, event)
        time.sleep(1.0 / rate)


def run_brute_force(producer: Producer, tenant_id: str, rate: float) -> None:
    """
    Simulates a brute-force attack loop:
      1. A few normal events (background noise)
      2. Burst of 4625 failures from one external IP targeting one account
      3. Optionally a 4624 success (attacker got in)
      4. Sleep, repeat

    This is what brute_force.yml should detect: >=5 failures from
    the same IP within a sliding window.
    """
    print(f"[brute_force] Attack simulation — {rate:.1f} evt/s — Ctrl+C to stop")
    print()
    while True:
        # Background noise between attacks
        noise_count = random.randint(2, 5)
        for _ in range(noise_count):
            user = random.choice(USERS)
            event = make_4624(user, random.choice(INTERNAL_IPS),
                              random.choice(WORKSTATIONS), tenant_id)
            _send(producer, event)
            time.sleep(0.8 / rate)

        # Attack burst
        target = random.choice(HIGH_VALUE_ACCOUNTS + USERS)
        attacker_ip = _random_external_ip()
        burst_count = random.randint(6, 14)
        print(f"\n  [!] ATTACK: {burst_count} attempts → {target!r} from {attacker_ip}")

        for _ in range(burst_count):
            status = random.choice([STATUS_WRONG_PASSWORD, STATUS_WRONG_PASSWORD, STATUS_USER_NOT_FOUND])
            event = make_4625(target, attacker_ip, DC_HOST, tenant_id, status=status)
            _send(producer, event)
            time.sleep(0.25 / rate)   # rapid-fire

        # 35% chance attacker succeeds
        if random.random() < 0.35:
            event = make_4624(target, attacker_ip, DC_HOST, tenant_id,
                              logon_type=LOGON_TYPE_NETWORK)
            _send(producer, event)
            print(f"  [!] BRUTE FORCE SUCCEEDED for {target!r} — 4624 generated")

        print(f"  Sleeping before next attack burst...\n")
        time.sleep(8.0 / rate)


def run_new_account(producer: Producer, tenant_id: str, rate: float) -> None:
    """
    Simulates periodic account creation (legitimate and suspicious).
    4720 events — new_account_creation.yml should detect these.

    In real environments: sysadmins create service accounts legitimately,
    but attackers also create backdoor accounts after gaining foothold.
    """
    print(f"[new_account] Account creation events — {rate:.1f} evt/s — Ctrl+C to stop")
    print()
    counter = 0
    while True:
        counter += 1
        actor = random.choice(USERS[:4])   # senior users do account admin
        new_user = random.choice([
            f"svc_acct_{counter:04d}",     # service account pattern
            f"backup_usr_{counter}",        # backup account
            f"tmp_{random.randint(1000,9999)}",  # suspicious temp account
        ])
        event = make_4720(new_user, actor, DC_HOST, tenant_id)
        _send(producer, event)
        print(f"  4720: {new_user!r} created by {actor!r}")
        time.sleep(5.0 / rate)


def run_mixed(producer: Producer, tenant_id: str, rate: float) -> None:
    """
    Interleaves all three scenarios randomly, weighted toward normal traffic.

    Probability weights:
      60%  normal logon events (4624 success or 4625 failure)
      30%  brute force attack bursts
      10%  new account creation
    """
    print(f"[mixed] Mixed scenario — {rate:.1f} evt/s — Ctrl+C to stop")
    print()
    bf_burst_remaining = 0
    bf_attacker_ip = None
    bf_target = None

    while True:
        roll = random.random()

        if bf_burst_remaining > 0:
            # Finish current brute force burst
            status = random.choice([STATUS_WRONG_PASSWORD, STATUS_WRONG_PASSWORD, STATUS_USER_NOT_FOUND])
            event = make_4625(bf_target, bf_attacker_ip, DC_HOST, tenant_id, status=status)
            _send(producer, event)
            bf_burst_remaining -= 1

            if bf_burst_remaining == 0 and random.random() < 0.35:
                event = make_4624(bf_target, bf_attacker_ip, DC_HOST, tenant_id)
                _send(producer, event)
                print(f"  [!] BRUTE FORCE SUCCEEDED for {bf_target!r}")

        elif roll < 0.60:
            # Normal auth event
            user = random.choice(USERS)
            ip = random.choice(INTERNAL_IPS)
            computer = random.choice(WORKSTATIONS)
            if random.random() < 0.82:
                event = make_4624(user, ip, computer, tenant_id)
            else:
                event = make_4625(user, ip, computer, tenant_id)
            _send(producer, event)

        elif roll < 0.90:
            # Start a new brute force burst
            bf_target = random.choice(HIGH_VALUE_ACCOUNTS + USERS)
            bf_attacker_ip = _random_external_ip()
            bf_burst_remaining = random.randint(6, 14)
            print(f"\n  [!] ATTACK starting: {bf_burst_remaining} attempts → {bf_target!r} from {bf_attacker_ip}")

        else:
            # Account creation
            actor = random.choice(USERS[:4])
            new_user = f"svc_{random.randint(1000, 9999)}"
            event = make_4720(new_user, actor, DC_HOST, tenant_id)
            _send(producer, event)

        time.sleep(1.0 / rate)


# ── Entry point ───────────────────────────────────────────────────────────────

SCENARIOS = {
    "normal": run_normal,
    "brute_force": run_brute_force,
    "new_account": run_new_account,
    "mixed": run_mixed,
}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Drishti synthetic Windows Security Event generator",
        epilog="Run without args for mixed mode at 1 evt/s.",
    )
    parser.add_argument(
        "--scenario", "-s",
        choices=list(SCENARIOS),
        default="mixed",
        help="Event scenario (default: mixed)",
    )
    parser.add_argument(
        "--rate", "-r",
        type=float,
        default=1.0,
        metavar="N",
        help="Events per second (default: 1.0)",
    )
    parser.add_argument(
        "--tenant", "-t",
        default="demo",
        metavar="ID",
        help="tenant_id embedded in every event (default: demo)",
    )
    args = parser.parse_args()

    if args.rate <= 0:
        print("--rate must be > 0", file=sys.stderr)
        sys.exit(1)

    producer = Producer({
        "bootstrap.servers": BOOTSTRAP_SERVERS,
        "linger.ms": 0,        # send immediately, no batching delay
        "acks": "1",           # leader ack only — acceptable for test data
    })

    print("=" * 60)
    print("Drishti Windows event generator")
    print(f"  broker   : {BOOTSTRAP_SERVERS}")
    print(f"  topic    : {OUTPUT_TOPIC}")
    print(f"  scenario : {args.scenario}")
    print(f"  rate     : {args.rate} evt/s")
    print(f"  tenant   : {args.tenant}")
    print("=" * 60)
    print()

    try:
        SCENARIOS[args.scenario](producer, args.tenant, args.rate)
    except KeyboardInterrupt:
        print("\n[tap OFF] stopped.")
    finally:
        producer.flush()


if __name__ == "__main__":
    main()