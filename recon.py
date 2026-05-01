#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import json
import re
import shlex
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path


ASCII_ART = r"""
 ____  _____ ____ ___  _   _   ______   __
|  _ \| ____/ ___/ _ \| \ | | |  _ \ \ / /
| |_) |  _|| |  | | | |  \| | | |_) \ V /
|  _ <| |__| |__| |_| | |\  |_|  __/ | |
|_| \_\_____\____\___/|_| \_(_)_|    |_|
"""


class Style:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    GRAY = "\033[90m"


USE_COLOR = True
KEEP_LOGS = False
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


class TerminalRecorder:
    def __init__(self, stream, report_path: Path):
        self.stream = stream
        self.report = report_path.open("w", encoding="utf-8")

    def write(self, data: str) -> int:
        self.stream.write(data)
        self.report.write(ANSI_RE.sub("", data))
        return len(data)

    def flush(self) -> None:
        self.stream.flush()
        self.report.flush()

    def close(self) -> None:
        self.report.close()

WINDOWS_PORTS = {88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 3389, 5985, 5986, 9389}
AD_PORTS = {53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269, 9389}
COMMON_SHARES = {"ADMIN$", "C$", "D$", "E$", "IPC$", "NETLOGON", "SYSVOL", "PRINT$"}
WINDOWS_KEYWORDS = (
    "microsoft-ds",
    "msrpc",
    "netbios",
    "kerberos",
    "ldap",
    "winrm",
    "rdp",
)


@dataclass
class ServiceEntry:
    port: int
    protocol: str
    service: str
    details: str


@dataclass
class CommandRecord:
    name: str
    command: list[str]
    output_file: str
    returncode: int


@dataclass
class ReconSummary:
    target: str
    requested_os: str
    detected_os: str
    probable_active_directory: bool
    open_ports: list[int]
    services: list[ServiceEntry]
    domain_names: list[str]
    dc_names: list[str]
    run_directory: str
    commands: list[CommandRecord]
    findings: dict[str, list[str]]
    generated_at: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Terminal recon helper for HTB-style boxes with ASCII banner, Nmap orchestration and quick Windows/Linux/AD hints."
    )
    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("--os", choices=("auto", "windows", "linux"), default="auto", help="Expected host family")
    parser.add_argument("--output-root", default="runs", help="Directory where each run is stored")
    parser.add_argument("--min-rate", type=int, default=1000, help="Nmap minimum packet rate for the full port scan")
    parser.add_argument("--max-rtt-timeout", default="1000ms", help="Nmap max RTT timeout for the full port scan")
    parser.add_argument("--max-retries", type=int, default=5, help="Nmap max retries for the full port scan")
    parser.add_argument("--skip-full-scan", action="store_true", help="Skip the initial full TCP port scan")
    parser.add_argument("--skip-service-scan", action="store_true", help="Skip the follow-up service scan")
    parser.add_argument("--skip-vuln-scan", action="store_true", help="Skip the vuln script scan")
    parser.add_argument("--skip-ad-enum", action="store_true", help="Skip AD-specific commands even if AD is detected")
    parser.add_argument("--ad", choices=("auto", "yes", "no"), default="auto", help="Force AD flow or disable it")
    parser.add_argument("--domain", help="AD domain, for example htb.local")
    parser.add_argument("--dc-ip", help="Domain controller IP. Defaults to target when omitted")
    parser.add_argument("--username", "-u", help="Username for authenticated AD checks")
    parser.add_argument("--password", "-p", help="Password for authenticated AD checks")
    parser.add_argument("--user-wordlist", help="User wordlist for Kerberos user enum or spray mode")
    parser.add_argument("--ldap-base", help="LDAP base DN, for example DC=HTB,DC=LOCAL")
    parser.add_argument("--share", default="SYSVOL", help="SMB share to test with creds")
    parser.add_argument("--targets-file", help="Targets file for spray mode")
    parser.add_argument("--enable-spray", action="store_true", help="Explicitly enable password spray commands")
    parser.add_argument("--spray-password", help="Password to use when --enable-spray is set")
    parser.add_argument("--spray-protocols", default="smb,winrm,mssql,rdp", help="Comma-separated protocols for spray mode")
    parser.add_argument("--auth-fail-limit", type=int, default=3, help="NetExec auth fail limit for spray mode")
    parser.add_argument("--spray-delay", type=int, default=5, help="Delay used by NetExec spray mode")
    parser.add_argument("--no-color", action="store_true", help="Disable colored terminal output")
    parser.add_argument("--show-commands", action="store_true", help="Show each command before execution")
    parser.add_argument("--verbose-output", action="store_true", help="Print command output live instead of only saving logs")
    parser.add_argument("--command-timeout", type=int, default=120, help="Max seconds before killing a stuck enum command")
    parser.add_argument("--nmap-timeout", type=int, default=900, help="Max seconds before killing a stuck Nmap command")
    parser.add_argument("--fast", action="store_true", help="Skip slower AD modules and keep only high-signal quick checks")
    parser.add_argument("--keep-logs", action="store_true", help="Keep all intermediate command logs instead of only report.txt")
    parser.add_argument("--html-report", action="store_true", help="Also write a formatted HTML report")
    parser.add_argument("--dry-run", action="store_true", help="Print commands and prepare output folders without executing scans")
    args, unknown = parser.parse_known_args()
    if unknown:
        parser.error(f"unrecognized arguments: {' '.join(unknown)}. Use -u/--username and -p/--password for credentials.")
    return args


def sanitize_target(target: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", target)


def create_run_dir(output_root: str, target: str) -> Path:
    run_dir = Path(output_root)
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir.resolve()


def create_session_id(target: str) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{sanitize_target(target)}_{timestamp}"


def ensure_tool(tool_name: str) -> None:
    if shutil.which(tool_name):
        return
    raise SystemExit(f"Missing required tool: {tool_name}")


def tool_exists(tool_name: str) -> bool:
    return shutil.which(tool_name) is not None


def print_banner() -> None:
    width = terminal_width()
    print(color("=" * width, Style.CYAN + Style.BOLD))
    print(color(ASCII_ART.rstrip(), Style.MAGENTA + Style.BOLD))
    print(color(" HTB / LAB RECON AUTOMATION ".center(width, "-"), Style.CYAN + Style.BOLD))
    print(color(" terminal-first recon automation | output: curated ".center(width), Style.GRAY))
    print(color("=" * width, Style.CYAN + Style.BOLD))


def color(text: str, style: str) -> str:
    if not USE_COLOR:
        return text
    return f"{style}{text}{Style.RESET}"


def terminal_width() -> int:
    return min(shutil.get_terminal_size((100, 20)).columns, 120)


def section(title: str) -> None:
    width = terminal_width()
    label = f" {title.upper()} "
    line = label.center(width, "=")
    print("\n" + color(line, Style.BLUE + Style.BOLD))


def subsection(title: str) -> None:
    print("\n" + color(f"[+] {title}", Style.GREEN + Style.BOLD))


def warn(message: str) -> None:
    print(color(f"[!] {message}", Style.YELLOW + Style.BOLD))


def fail(message: str) -> None:
    print(color(f"[x] {message}", Style.RED + Style.BOLD))


def command_line(command: list[str]) -> None:
    print(color("$ ", Style.GRAY) + color(shlex.join(redact_command(command)), Style.CYAN))


def kv(label: str, value: str, value_style: str = Style.RESET) -> None:
    print(f"  {color((label + ':').ljust(18), Style.BOLD)} {color(value, value_style)}")


def status_style(value: str) -> str:
    normalized = value.lower()
    if normalized in {"yes", "windows", "linux"}:
        return Style.GREEN + Style.BOLD
    if normalized in {"no", "unknown", "none"}:
        return Style.YELLOW + Style.BOLD
    return Style.CYAN


def redact_command(command: list[str]) -> list[str]:
    redacted: list[str] = []
    hide_next = False
    secret_flags = {"-p", "--password", "-w", "--spray-password"}
    for part in command:
        if hide_next:
            redacted.append("<redacted>")
            hide_next = False
            continue
        redacted_part = re.sub(r"%[^\s]+", "%<redacted>", part)
        redacted.append(redacted_part)
        if part in secret_flags:
            hide_next = True
    return redacted


def truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 3)] + "..."


def print_table(headers: list[str], rows: list[list[str]], *, title: str | None = None) -> None:
    if title:
        subsection(title)
    if not rows:
        print("  " + color("none", Style.YELLOW))
        return

    width = terminal_width()
    usable = max(40, width - 7)
    column_count = len(headers)
    base_width = max(12, usable // column_count)
    widths = [base_width] * column_count
    widths[-1] += usable - sum(widths)

    def row_line(values: list[str]) -> str:
        cells = [truncate(str(value), widths[index]).ljust(widths[index]) for index, value in enumerate(values)]
        return "| " + " | ".join(cells) + " |"

    border = "+-" + "-+-".join("-" * width for width in widths) + "-+"
    print("  " + color(border, Style.GRAY))
    print("  " + color(row_line(headers), Style.BOLD))
    print("  " + color(border, Style.GRAY))
    for row in rows:
        print("  " + row_line(row))
    print("  " + color(border, Style.GRAY))


def print_card(title: str, rows: list[tuple[str, str]]) -> None:
    subsection(title)
    for label, value in rows:
        kv(label, value or "none", status_style(value or "none"))


def command_state(record: CommandRecord) -> str:
    if record.returncode == 0:
        return "ok"
    if record.returncode == 125:
        return "skipped"
    if record.returncode == 127:
        return "missing"
    return f"exit {record.returncode}"


def command_state_style(state: str) -> str:
    if state == "ok":
        return Style.GREEN + Style.BOLD
    if state == "missing":
        return Style.YELLOW + Style.BOLD
    if state == "skipped":
        return Style.GRAY
    return Style.RED + Style.BOLD


def print_finding_list(title: str, values: list[str], style: str = Style.CYAN, limit: int = 12) -> None:
    print(color(f"\n  {title}", Style.BOLD))
    if not values:
        print("    " + color("none", Style.YELLOW))
        return
    for value in values[:limit]:
        print("    " + color("- ", Style.GRAY) + color(value, style))
    if len(values) > limit:
        print("    " + color(f"+ {len(values) - limit} more in logs", Style.GRAY))


def run_command(
    name: str,
    command: list[str],
    output_file: Path,
    dry_run: bool,
    verbose_output: bool = False,
    show_commands: bool = False,
    timeout_seconds: int = 300,
) -> CommandRecord:
    if dry_run or show_commands:
        subsection(name)
        command_line(command)
        print(color(f"log -> {output_file}", Style.DIM))
    else:
        print(color(f"[run] {name:<32}", Style.CYAN), end="", flush=True)

    if dry_run:
        output_file.write_text("[dry-run]\n", encoding="utf-8")
        print(color("mode -> dry-run, command not executed", Style.YELLOW))
        return CommandRecord(name=name, command=command, output_file=str(output_file), returncode=0)

    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True) as process:
        try:
            output, _ = process.communicate(timeout=timeout_seconds)
            returncode = process.returncode
        except subprocess.TimeoutExpired:
            process.kill()
            output, _ = process.communicate()
            output = f"{output}\n[timeout] Command killed after {timeout_seconds}s.\n"
            returncode = 124

    if verbose_output and output:
        print(output, end="" if output.endswith("\n") else "\n")

    output_file.write_text(output, encoding="utf-8")

    if returncode != 0:
        if dry_run or show_commands or verbose_output:
            fail(f"{name} exited with code {returncode}")
        else:
            print(color(f" exit {returncode}", Style.RED + Style.BOLD))
    else:
        if dry_run or show_commands or verbose_output:
            print(color(f"[ok] {name} completed", Style.GREEN + Style.BOLD))
        else:
            print(color(" ok", Style.GREEN + Style.BOLD))

    return CommandRecord(name=name, command=command, output_file=str(output_file), returncode=returncode)


def run_optional_command(
    name: str,
    command: list[str],
    output_file: Path,
    dry_run: bool,
    verbose_output: bool = False,
    show_commands: bool = False,
    timeout_seconds: int = 300,
) -> CommandRecord:
    tool_name = command[0]
    if not dry_run and not tool_exists(tool_name):
        print()
        warn(f"{name}: missing tool '{tool_name}', skipping")
        output_file.write_text(f"[skipped] Missing tool: {tool_name}\n", encoding="utf-8")
        return CommandRecord(name=name, command=command, output_file=str(output_file), returncode=127)
    return run_command(name, command, output_file, dry_run, verbose_output, show_commands, timeout_seconds)


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="ignore")


def parse_open_ports(scan_text: str) -> list[int]:
    ports: list[int] = []
    for line in scan_text.splitlines():
        match = re.match(r"^(\d+)/(tcp|udp)\s+open\b", line.strip())
        if match:
            ports.append(int(match.group(1)))
    return sorted(set(ports))


def parse_services(scan_text: str) -> list[ServiceEntry]:
    services: list[ServiceEntry] = []
    for line in scan_text.splitlines():
        match = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$", line.strip())
        if not match:
            continue
        services.append(
            ServiceEntry(
                port=int(match.group(1)),
                protocol=match.group(2),
                service=match.group(3),
                details=(match.group(4) or "").strip(),
            )
        )
    return services


def ordered_unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        normalized = item.strip().strip(".")
        if not normalized:
            continue
        key = normalized.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(normalized)
    return result


def normalize_domain(value: str) -> str:
    domain = value.strip().strip(".").lower()
    domain = re.sub(r"0$", "", domain)
    return domain


def split_fqdn(value: str) -> tuple[str | None, str | None]:
    cleaned = value.strip().strip(".")
    if "." not in cleaned:
        return cleaned or None, None
    hostname, domain = cleaned.split(".", 1)
    return hostname or None, normalize_domain(domain)


def extract_domains(scan_text: str) -> list[str]:
    direct_matches: list[str] = []
    fqdn_matches: list[str] = []
    patterns = (
        r"(?im)(?:domain(?: name)?|dns_domain_name|forest name|forest|workgroup)\s*[:=]\s*([A-Za-z0-9._-]+)",
        r"(?im)Subject Alternative Name:\s*DNS:([A-Za-z0-9._-]+)",
    )
    for pattern in patterns:
        direct_matches.extend(re.findall(pattern, scan_text))
    fqdn_matches.extend(re.findall(r"(?im)commonName=([A-Za-z0-9._-]+\.[A-Za-z]{2,}0?)", scan_text))
    fqdn_matches.extend(re.findall(r"(?im)\b([A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z]{2,}0?)\b", scan_text))
    domains: list[str] = []
    for match in direct_matches:
        value = match.strip().strip(".")
        if not value:
            continue
        domains.append(normalize_domain(value))
    for match in fqdn_matches:
        _, domain = split_fqdn(match)
        if domain:
            domains.append(domain)
    return ordered_unique(domains)


def extract_dc_names(scan_text: str) -> list[str]:
    matches: list[str] = []
    patterns = (
        r"(?im)(?:computer name|netbios computer name|server name|hostname)\s*[:=]\s*([A-Za-z0-9._-]+)",
        r"(?im)Target_Name:\s*([A-Za-z0-9._-]+)",
    )
    for pattern in patterns:
        matches.extend(re.findall(pattern, scan_text))
    matches.extend(re.findall(r"(?im)\b([A-Za-z0-9_-]+\.[A-Za-z0-9._-]+\.[A-Za-z]{2,}0?)\b", scan_text))
    dc_names: list[str] = []
    for match in matches:
        hostname, _ = split_fqdn(match)
        if hostname:
            dc_names.append(hostname.upper())
    return ordered_unique(dc_names)


def detect_os(requested_os: str, open_ports: list[int], services: list[ServiceEntry], scan_text: str) -> str:
    if requested_os != "auto":
        return requested_os

    windows_score = 0
    linux_score = 0

    windows_score += sum(1 for port in open_ports if port in WINDOWS_PORTS)
    linux_score += sum(1 for port in open_ports if port in {22, 111})

    lower_text = scan_text.lower()
    for keyword in WINDOWS_KEYWORDS:
        if keyword in lower_text:
            windows_score += 2

    if "openssh" in lower_text:
        linux_score += 2

    if windows_score > linux_score:
        return "windows"
    if linux_score > windows_score:
        return "linux"
    return "unknown"


def detect_active_directory(open_ports: list[int], scan_text: str, domains: list[str]) -> bool:
    matched_ports = len([port for port in open_ports if port in AD_PORTS])
    keywords = ("kerberos", "ldap", "active directory", "domain controller", "msrpc", "microsoft-ds")
    lower_text = scan_text.lower()
    keyword_hits = sum(1 for keyword in keywords if keyword in lower_text)
    return matched_ports >= 3 or keyword_hits >= 2 or (matched_ports >= 2 and bool(domains))


def domain_to_base_dn(domain: str | None) -> str | None:
    if not domain:
        return None
    parts = [part for part in domain.split(".") if part]
    if not parts:
        return None
    return ",".join(f"DC={part}" for part in parts)


def add_command(commands: list[tuple[str, list[str], str]], name: str, command: list[str], output_name: str) -> None:
    commands.append((name, command, output_name))


def build_ad_commands(args: argparse.Namespace, dc_ip: str) -> list[tuple[str, list[str], str]]:
    commands: list[tuple[str, list[str], str]] = []
    domain = args.domain
    username = args.username
    password = args.password
    has_creds = bool(username and password)
    ldap_base = args.ldap_base or domain_to_base_dn(domain)

    if args.fast:
        add_command(commands, "NetExec SMB null banner", ["netexec", "smb", dc_ip, "-u", "", "-p", ""], "ad_nxc_smb_null.txt")
        add_command(commands, "NetExec SMB null shares", ["netexec", "smb", dc_ip, "-u", "", "-p", "", "--shares"], "ad_nxc_smb_null_shares.txt")
        add_command(commands, "NetExec LDAP null users", ["netexec", "ldap", dc_ip, "-u", "", "-p", "", "--users"], "ad_nxc_ldap_null_users.txt")
        if domain:
            add_command(commands, "DNS SRV DC discovery", ["dig", f"_ldap._tcp.dc._msdcs.{domain}", "SRV", f"@{dc_ip}"], "ad_dns_srv_dc.txt")
        if username and password:
            add_command(commands, "NetExec SMB auth users", ["netexec", "smb", dc_ip, "-u", username, "-p", password, "--users"], "ad_nxc_smb_auth_users.txt")
            add_command(commands, "NetExec SMB auth shares", ["netexec", "smb", dc_ip, "-u", username, "-p", password, "--shares"], "ad_nxc_smb_auth_shares.txt")
            add_command(commands, "NetExec SMB loggedon users", ["netexec", "smb", dc_ip, "-u", username, "-p", password, "--loggedon-users"], "ad_nxc_smb_loggedon_users.txt")
            add_command(commands, "NetExec GPP password", ["netexec", "smb", dc_ip, "-u", username, "-p", password, "-M", "gpp_password"], "ad_nxc_gpp_password.txt")
            add_command(commands, "NetExec GPP autologin", ["netexec", "smb", dc_ip, "-u", username, "-p", password, "-M", "gpp_autologin"], "ad_nxc_gpp_autologin.txt")
        return commands

    add_command(commands, "Enum4linux-ng null session", ["enum4linux-ng", "-A", dc_ip], "ad_enum4linux_ng_all.txt")
    add_command(commands, "Enum4linux-ng users", ["enum4linux-ng", "-U", dc_ip], "ad_enum4linux_ng_users.txt")
    add_command(commands, "RPC null enumdomusers", ["rpcclient", "-U", "", "-N", dc_ip, "-c", "enumdomusers"], "ad_rpcclient_enumdomusers.txt")
    add_command(commands, "LookupSID guest no-pass", ["lookupsid.py", f"guest@{dc_ip}", "-no-pass"], "ad_lookupsid_guest.txt")
    add_command(commands, "NetExec SMB null banner", ["netexec", "smb", dc_ip, "-u", "", "-p", ""], "ad_nxc_smb_null.txt")
    add_command(commands, "NetExec SMB null RID brute", ["netexec", "smb", dc_ip, "-u", "", "-p", "", "--rid-brute"], "ad_nxc_smb_null_rid_brute.txt")
    add_command(commands, "NetExec SMB null users", ["netexec", "smb", dc_ip, "-u", "", "-p", "", "--users"], "ad_nxc_smb_null_users.txt")
    add_command(commands, "NetExec SMB Guest users", ["netexec", "smb", dc_ip, "-u", "Guest", "-p", "", "--users"], "ad_nxc_smb_guest_users.txt")
    add_command(commands, "NetExec SMB null shares", ["netexec", "smb", dc_ip, "-u", "", "-p", "", "--shares"], "ad_nxc_smb_null_shares.txt")
    add_command(commands, "SMBClient anonymous shares", ["smbclient", "-N", "-L", f"//{dc_ip}"], "ad_smbclient_null_shares.txt")

    if domain:
        add_command(commands, "DNS SRV DC discovery", ["dig", f"_ldap._tcp.dc._msdcs.{domain}", "SRV", f"@{dc_ip}"], "ad_dns_srv_dc.txt")

    if domain and args.user_wordlist:
        add_command(commands, "Kerbrute user enum", ["kerbrute", "userenum", "--dc", dc_ip, "-d", domain, args.user_wordlist], "ad_kerbrute_userenum.txt")

    if ldap_base:
        add_command(commands, "LDAP anonymous basic dump", ["ldapsearch", "-x", "-H", f"ldap://{dc_ip}", "-b", ldap_base, "(objectClass=*)", "dn", "sAMAccountName", "userPrincipalName", "memberOf", "-E", "pr=2000/noprompt"], "ad_ldapsearch_anonymous.txt")
        add_command(commands, "LDAP anonymous users", ["ldapsearch", "-x", "-H", f"ldap://{dc_ip}", "-b", ldap_base, "(&(objectClass=user))", "sAMAccountName"], "ad_ldapsearch_users.txt")

    add_command(commands, "NetExec LDAP null users", ["netexec", "ldap", dc_ip, "-u", "", "-p", "", "--users"], "ad_nxc_ldap_null_users.txt")

    if has_creds:
        auth_user = f"{domain}/{username}%{password}" if domain else f"{username}%{password}"
        rpc_auth = f"{domain}/{username}%{password}" if domain else f"{username}%{password}"
        add_command(commands, "RPC auth enumdomusers", ["rpcclient", "-U", rpc_auth, dc_ip, "-c", "enumdomusers"], "ad_rpcclient_auth_enumdomusers.txt")
        add_command(commands, "RPC auth querydispinfo", ["rpcclient", "-U", rpc_auth, dc_ip, "-c", "querydispinfo"], "ad_rpcclient_auth_querydispinfo.txt")
        add_command(commands, "RPC auth enumdomgroups", ["rpcclient", "-U", rpc_auth, dc_ip, "-c", "enumdomgroups"], "ad_rpcclient_auth_enumdomgroups.txt")
        add_command(commands, "SMBClient authenticated shares", ["smbclient", "-U", auth_user, "-L", f"//{dc_ip}"], "ad_smbclient_auth_shares.txt")
        add_command(commands, "SMBClient authenticated share", ["smbclient", "-U", auth_user, f"//{dc_ip}/{args.share}", "-c", "ls; quit"], "ad_smbclient_auth_share.txt")
        add_command(commands, "NetExec SMB auth users", ["netexec", "smb", dc_ip, "-u", username, "-p", password, "--users"], "ad_nxc_smb_auth_users.txt")
        add_command(commands, "NetExec SMB auth groups", ["netexec", "smb", dc_ip, "-u", username, "-p", password, "--groups"], "ad_nxc_smb_auth_groups.txt")
        add_command(commands, "NetExec SMB loggedon users", ["netexec", "smb", dc_ip, "-u", username, "-p", password, "--loggedon-users"], "ad_nxc_smb_loggedon_users.txt")
        add_command(commands, "NetExec SMB auth shares", ["netexec", "smb", dc_ip, "-u", username, "-p", password, "--shares"], "ad_nxc_smb_auth_shares.txt")
        add_command(commands, "NetExec spider_plus", ["netexec", "smb", dc_ip, "-u", username, "-p", password, "-M", "spider_plus"], "ad_nxc_spider_plus.txt")
        add_command(commands, "NetExec GPP password", ["netexec", "smb", dc_ip, "-u", username, "-p", password, "-M", "gpp_password"], "ad_nxc_gpp_password.txt")
        add_command(commands, "NetExec GPP autologin", ["netexec", "smb", dc_ip, "-u", username, "-p", password, "-M", "gpp_autologin"], "ad_nxc_gpp_autologin.txt")

        if domain:
            add_command(commands, "LDAP domain dump", ["ldapdomaindump", f"ldap://{dc_ip}", "-u", f"{domain}\\{username}", "-p", password], "ad_ldapdomaindump.txt")
            add_command(commands, "ADIDNS dump", ["adidnsdump", "-u", f"{username}@{domain}", "-p", password, domain], "ad_adidnsdump.txt")

        if ldap_base and domain:
            add_command(commands, "LDAP descriptions with creds", ["ldapsearch", "-x", "-H", f"ldap://{dc_ip}", "-D", f"{username}@{domain}", "-w", password, "-b", ldap_base, "(&(objectClass=user)(description=*))", "sAMAccountName", "description"], "ad_ldapsearch_descriptions.txt")

    if args.enable_spray:
        spray_target = args.targets_file or dc_ip
        if not args.user_wordlist or not args.spray_password:
            add_command(commands, "Spray not configured", ["missing", "--user-wordlist", "or", "--spray-password"], "ad_spray_not_configured.txt")
        else:
            protocols = [item.strip() for item in args.spray_protocols.split(",") if item.strip()]
            for protocol in protocols:
                command = ["netexec", protocol, spray_target, "-u", args.user_wordlist, "-p", args.spray_password, "--continue-on-success"]
                if protocol == "smb":
                    command.extend(["--auth-fail-limit", str(args.auth_fail_limit), "--delay", str(args.spray_delay)])
                add_command(commands, f"NetExec {protocol} password spray", command, f"ad_spray_{sanitize_target(protocol)}.txt")

    return commands


def run_ad_flow(
    args: argparse.Namespace,
    run_dir: Path,
    dc_ip: str,
    dry_run: bool,
    verbose_output: bool,
    show_commands: bool,
    timeout_seconds: int,
) -> list[CommandRecord]:
    records: list[CommandRecord] = []
    section("Active Directory flow")
    for name, command, output_name in build_ad_commands(args, dc_ip):
        output_file = run_dir / output_name
        skip_reason = duplicate_skip_reason(name, run_dir)
        if skip_reason and not dry_run:
            print(color(f"[skip] {name:<31} {skip_reason}", Style.GRAY))
            output_file.write_text(f"[skipped] {skip_reason}\n", encoding="utf-8")
            records.append(CommandRecord(name=name, command=command, output_file=str(output_file), returncode=125))
            continue
        if command[0] == "missing":
            print()
            warn(f"{name}: missing required spray options")
            output_file.write_text("[skipped] Configure --user-wordlist and --spray-password to enable spray commands.\n", encoding="utf-8")
            records.append(CommandRecord(name=name, command=command, output_file=str(output_file), returncode=2))
            continue
        records.append(run_optional_command(name, command, output_file, dry_run, verbose_output, show_commands, timeout_seconds))
    if not args.fast:
        records.extend(run_nonstandard_share_crawl(args, run_dir, dc_ip, dry_run, verbose_output, show_commands, timeout_seconds))
    return records


def duplicate_skip_reason(command_name: str, run_dir: Path) -> str | None:
    purpose = command_purpose(command_name)
    if not purpose:
        return None
    findings = extract_findings(run_dir, [], [], [])
    if purpose == "users" and findings.get("users"):
        return "users already found by previous module"
    if purpose == "groups" and findings.get("groups"):
        return "groups already found by previous module"
    if purpose == "shares" and findings.get("shares"):
        return "shares already found by previous module"
    return None


def command_purpose(command_name: str) -> str | None:
    name = command_name.lower()
    if any(token in name for token in ("loggedon", "spider", "gpp", "domain dump", "adidns", "descriptions")):
        return None
    if any(token in name for token in ("users", "enumdomusers", "querydispinfo", "user enum")):
        return "users"
    if "groups" in name or "enumdomgroups" in name:
        return "groups"
    if "shares" in name:
        return "shares"
    return None


def run_nonstandard_share_crawl(
    args: argparse.Namespace,
    run_dir: Path,
    dc_ip: str,
    dry_run: bool,
    verbose_output: bool,
    show_commands: bool,
    timeout_seconds: int,
) -> list[CommandRecord]:
    findings = extract_findings(run_dir, [], [], [])
    shares = findings.get("nonstandard_shares", [])
    if not shares:
        return []

    auth_user = None
    if args.username and args.password:
        auth_user = f"{args.domain}/{args.username}%{args.password}" if args.domain else f"{args.username}%{args.password}"

    records: list[CommandRecord] = []
    subsection("Non-standard share crawl")
    for share in shares[:10]:
        safe_share = sanitize_target(share)
        output_file = run_dir / f"share_crawl_{safe_share}.txt"
        if auth_user:
            command = ["smbclient", "-U", auth_user, f"//{dc_ip}/{share}", "-c", "recurse; ls; quit"]
        else:
            command = ["smbclient", "-N", f"//{dc_ip}/{share}", "-c", "recurse; ls; quit"]
        records.append(
            run_optional_command(
                f"Crawl share {share}",
                command,
                output_file,
                dry_run,
                verbose_output,
                show_commands,
                timeout_seconds,
            )
        )
    return records


def build_follow_up(summary: ReconSummary) -> list[str]:
    steps: list[str] = []

    if summary.probable_active_directory:
        steps.append("Host looks like an AD-backed Windows target; review SMB, Kerberos, LDAP and DNS exposure manually on the box you control.")
        steps.append("Use the detected domain/DC hints to drive your own authorized authenticated checks outside this helper.")
        return steps

    if summary.detected_os == "windows":
        steps.append("Windows indicators were found; review SMB, RPC, WinRM and RDP exposure manually if those services are open.")
        return steps

    if summary.detected_os == "linux":
        steps.append("Linux indicators were found; review SSH, web services and any file-sharing services exposed by the host.")
        return steps

    steps.append("OS detection stayed inconclusive; inspect the service scan output manually for stronger hints.")
    return steps


def extract_findings(run_dir: Path, services: list[ServiceEntry], domains: list[str], dc_names: list[str]) -> dict[str, list[str]]:
    combined = "\n".join(read_text(path) for path in sorted(run_dir.glob("*.txt")))
    findings: dict[str, list[str]] = {
        "interesting_services": [],
        "domains": domains[:],
        "dc_names": dc_names[:],
        "users": [],
        "shares": [],
        "nonstandard_shares": [],
        "common_shares": [],
        "interesting_files": [],
        "groups": [],
        "potential_credentials": [],
        "gpp_findings": [],
        "adcs_findings": [],
        "kerberoastable": [],
        "asrep_roastable": [],
        "delegation_findings": [],
        "privileged_findings": [],
        "possible_vulns": [],
    }

    for entry in services:
        if entry.port in WINDOWS_PORTS or entry.port in {21, 22, 80, 443, 8080, 8443}:
            findings["interesting_services"].append(f"{entry.port}/{entry.protocol} {entry.service} {entry.details}".strip())

    user_patterns = (
        r"(?im)user:\s*\[([^\]]+)\]",
        r"(?im)\\?([A-Za-z0-9._-]+)\s+\(SidTypeUser\)",
        r"(?im)^sAMAccountName:\s*(\S+)",
        r"(?im)VALID USERNAME:\s*([^\s]+)",
    )
    share_patterns = (
        r"(?im)^\s*Sharename\s+Type\s+Comment.*?$",
        r"(?im)^\s*([A-Za-z0-9_$.-]+)\s+(?:Disk|IPC|Printer)\b",
        r"(?im)\\\\[^\\\s]+\\([A-Za-z0-9_$.-]+)",
    )
    group_patterns = (
        r"(?im)group:\s*\[([^\]]+)\]",
        r"(?im)\\?([A-Za-z0-9 ._-]+)\s+\(SidTypeGroup\)",
    )
    vuln_patterns = (
        r"(?im)^\|\s+([^\n]*(?:VULNERABLE|CVE-[0-9-]+)[^\n]*)",
        r"(?im)(CVE-\d{4}-\d{4,7})",
    )
    credential_patterns = (
        r"(?im)^.*\b(?:password|passwd|pwd|pass|credential|creds|secret)\b\s*[:=]\s*[^\r\n]+",
        r"(?im)^.*\b(?:user|username|login)\b\s*[:=]\s*[^\r\n]+",
        r"(?im)^.*\bcpassword\b\s*[:=]\s*[^\r\n]+",
        r"(?im)^.*\b(?:gpp_password|gpp_autologin)\b.*$",
    )
    gpp_patterns = (
        r"(?im)^.*\bcpassword\b.*$",
        r"(?im)^.*\bGroups\.xml\b.*$",
        r"(?im)^.*\bServices\.xml\b.*$",
        r"(?im)^.*\bScheduledTasks\.xml\b.*$",
        r"(?im)^.*\bDataSources\.xml\b.*$",
        r"(?im)^.*\bPrinters\.xml\b.*$",
        r"(?im)^.*\bDrives\.xml\b.*$",
    )
    adcs_patterns = (
        r"(?im)^.*\bADCS\b.*$",
        r"(?im)^.*\bActive Directory Certificate Services\b.*$",
        r"(?im)^.*\bCertificate Services\b.*$",
        r"(?im)^.*\bCertSrv\b.*$",
        r"(?im)^.*\bcertsrv\b.*$",
        r"(?im)^.*\bcertfnsh\.asp\b.*$",
        r"(?im)^.*\bcertnew\.cer\b.*$",
        r"(?im)^.*\bCertEnroll\b.*$",
        r"(?im)^.*\bcertutil\b.*$",
        r"(?im)^.*\benterprise ca\b.*$",
        r"(?im)^.*\benrollment service\b.*$",
        r"(?im)^.*\bCertificate Authority\b.*$",
    )
    kerberoast_patterns = (
        r"(?im)^.*\bkerberoast(?:able|ing)?\b.*$",
        r"(?im)^.*\bServicePrincipalName\b.*$",
        r"(?im)^.*\bSPN\b.*$",
        r"(?im)^.*\bMSSQLSvc/[^\s]+.*$",
        r"(?im)^.*\bHTTP/[^\s]+.*$",
        r"(?im)^.*\bHOST/[^\s]+.*$",
    )
    asrep_patterns = (
        r"(?im)^.*\bASREP\b.*$",
        r"(?im)^.*\bAS-REP\b.*$",
        r"(?im)^.*\bDONT_REQ_PREAUTH\b.*$",
        r"(?im)^.*\bUF_DONT_REQUIRE_PREAUTH\b.*$",
        r"(?im)^.*\bpreauth(?:entication)? not required\b.*$",
    )
    delegation_patterns = (
        r"(?im)^.*\bunconstrained delegation\b.*$",
        r"(?im)^.*\bconstrained delegation\b.*$",
        r"(?im)^.*\bmsDS-AllowedToDelegateTo\b.*$",
        r"(?im)^.*\bTRUSTED_FOR_DELEGATION\b.*$",
        r"(?im)^.*\bTRUSTED_TO_AUTH_FOR_DELEGATION\b.*$",
    )
    privileged_patterns = (
        r"(?im)^.*\bDomain Admins\b.*$",
        r"(?im)^.*\bEnterprise Admins\b.*$",
        r"(?im)^.*\bAdministrators\b.*$",
        r"(?im)^.*\bAccount Operators\b.*$",
        r"(?im)^.*\bBackup Operators\b.*$",
        r"(?im)^.*\bServer Operators\b.*$",
        r"(?im)^.*\bDnsAdmins\b.*$",
    )

    for pattern in user_patterns:
        findings["users"].extend(re.findall(pattern, combined))
    for pattern in share_patterns[1:]:
        findings["shares"].extend(re.findall(pattern, combined))
    for pattern in group_patterns:
        findings["groups"].extend(re.findall(pattern, combined))
    for pattern in vuln_patterns:
        findings["possible_vulns"].extend(re.findall(pattern, combined))
    for pattern in credential_patterns:
        findings["potential_credentials"].extend(re.findall(pattern, combined))
    for pattern in gpp_patterns:
        findings["gpp_findings"].extend(re.findall(pattern, combined))
    for pattern in adcs_patterns:
        findings["adcs_findings"].extend(re.findall(pattern, combined))
    for pattern in kerberoast_patterns:
        findings["kerberoastable"].extend(re.findall(pattern, combined))
    for pattern in asrep_patterns:
        findings["asrep_roastable"].extend(re.findall(pattern, combined))
    for pattern in delegation_patterns:
        findings["delegation_findings"].extend(re.findall(pattern, combined))
    for pattern in privileged_patterns:
        findings["privileged_findings"].extend(re.findall(pattern, combined))
    findings["interesting_files"].extend(extract_interesting_files(run_dir))

    cleaned: dict[str, list[str]] = {}
    for key, values in findings.items():
        cleaned[key] = ordered_unique([value.strip() for value in values if value and not value.lower().startswith("sharename")])[:30]
    shares = cleaned.get("shares", [])
    cleaned["common_shares"] = [share for share in shares if share.upper() in COMMON_SHARES]
    cleaned["nonstandard_shares"] = [share for share in shares if share.upper() not in COMMON_SHARES]
    return cleaned


def extract_interesting_files(run_dir: Path) -> list[str]:
    interesting_ext = {
        "txt", "csv", "conf", "config", "ini", "xml", "json", "yml", "yaml", "kdbx",
        "ps1", "bat", "cmd", "vbs", "doc", "docx", "xls", "xlsx", "pdf", "zip", "7z", "rar",
    }
    hot_keywords = ("password", "passwd", "pwd", "pass", "credential", "creds", "secret", "backup", "bak", "config", "vpn", "ssh", "key", "token", "admin")
    files: list[str] = []

    for log_path in sorted(run_dir.glob("*.txt")):
        share = share_name_from_log(log_path)
        current_dir = ""
        for raw_line in read_text(log_path).splitlines():
            line = raw_line.strip()
            if not line:
                continue

            dir_match = re.match(r"^\\\\[^\\]+\\[^\\]+\\?(.*)$", line)
            if dir_match:
                current_dir = dir_match.group(1).strip("\\")
                continue

            file_match = re.match(r"^(.+?)\s+[AHSR]*\s+\d+\s+\w{3}\s+\w{3}\s+\d+\s+\d{1,2}:\d{2}:\d{2}\s+\d{4}$", line)
            if file_match:
                filename = file_match.group(1).strip()
            else:
                filename_match = re.search(r"([^\\/\s]+\.(?:[A-Za-z0-9]{2,6}))\b", line)
                if not filename_match:
                    continue
                filename = filename_match.group(1).strip()

            if filename in {".", ".."}:
                continue

            ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            lower_name = filename.lower()
            if ext not in interesting_ext and not any(keyword in lower_name for keyword in hot_keywords):
                continue

            category = classify_file(filename)
            location_parts = [part for part in (share, current_dir, filename) if part]
            files.append(f"[{category}] " + "/".join(location_parts))

    return ordered_unique(files)


def share_name_from_log(log_path: Path) -> str:
    match = re.match(r"share_crawl_(.+)\.txt$", log_path.name)
    if not match:
        return ""
    return match.group(1).replace("_", " ")


def classify_file(filename: str) -> str:
    lower_name = filename.lower()
    ext = lower_name.rsplit(".", 1)[-1] if "." in lower_name else ""
    if any(keyword in lower_name for keyword in ("password", "passwd", "pwd", "cred", "secret", "token")):
        return "credential hint"
    if ext in {"kdbx", "key", "pem", "pfx", "p12"}:
        return "key material"
    if ext in {"config", "conf", "ini", "xml", "json", "yml", "yaml"}:
        return "config"
    if ext in {"ps1", "bat", "cmd", "vbs"}:
        return "script"
    if ext in {"doc", "docx", "xls", "xlsx", "pdf", "txt", "csv"}:
        return "document"
    if ext in {"zip", "7z", "rar"}:
        return "archive"
    if any(keyword in lower_name for keyword in ("backup", "bak")):
        return "backup"
    return "interesting"


def write_summary_files(summary: ReconSummary, run_dir: Path) -> None:
    if not (run_dir / ".keep_summary_json").exists():
        return

    json_path = run_dir / "summary.json"
    json_path.write_text(json.dumps(asdict(summary), indent=2), encoding="utf-8")


def write_html_report(txt_report: Path, html_report: Path, summary: ReconSummary) -> None:
    content = txt_report.read_text(encoding="utf-8", errors="ignore")
    escaped = html.escape(content)
    ad_status = "AD detected" if summary.probable_active_directory else "AD not detected"
    ports = ", ".join(str(port) for port in summary.open_ports) or "none"
    domains = ", ".join(summary.domain_names) or "none"
    dc_names = ", ".join(summary.dc_names) or "none"
    cards = [
        ("Target", summary.target),
        ("Detected OS", summary.detected_os),
        ("AD Status", ad_status),
        ("Open Ports", ports),
        ("Domains", domains),
        ("DC Names", dc_names),
    ]
    card_html = "\n".join(
        f"<article class=\"card\"><span>{html.escape(label)}</span><strong>{html.escape(value)}</strong></article>"
        for label, value in cards
    )

    priority_sections = [
        ("Kerberoastable", summary.findings.get("kerberoastable", []), "danger"),
        ("ASREP Roastable", summary.findings.get("asrep_roastable", []), "danger"),
        ("Delegation", summary.findings.get("delegation_findings", []), "danger"),
        ("ADCS", summary.findings.get("adcs_findings", []), "danger"),
        ("Potential Credentials", summary.findings.get("potential_credentials", []), "danger"),
        ("Non-standard Shares", summary.findings.get("nonstandard_shares", []), "warning"),
        ("Interesting Files", summary.findings.get("interesting_files", []), "warning"),
        ("Users", summary.findings.get("users", []), "info"),
        ("Groups", summary.findings.get("groups", []), "info"),
    ]
    finding_html = []
    for title, values, level in priority_sections:
        items = "".join(f"<li>{html.escape(value)}</li>" for value in values[:25]) or "<li class=\"muted\">none</li>"
        finding_html.append(f"<section class=\"finding {level}\"><h2>{html.escape(title)}</h2><ul>{items}</ul></section>")

    service_rows = "".join(
        "<tr>"
        f"<td>{entry.port}</td>"
        f"<td>{html.escape(entry.protocol)}</td>"
        f"<td>{html.escape(entry.service)}</td>"
        f"<td>{html.escape(entry.details or '-')}</td>"
        "</tr>"
        for entry in summary.services
    ) or "<tr><td colspan=\"4\" class=\"muted\">none</td></tr>"

    module_rows = "".join(
        "<tr>"
        f"<td><span class=\"state state-{html.escape(command_state(record).split()[0])}\">{html.escape(command_state(record))}</span></td>"
        f"<td>{html.escape(record.name)}</td>"
        "</tr>"
        for record in summary.commands
    )

    html_report.write_text(
        f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Vegas Recon Report</title>
  <style>
    :root {{ color-scheme: dark; --bg:#061018; --panel:#0d1826; --panel2:#101f31; --line:#24415f; --text:#d8e6f3; --muted:#7890a8; --cyan:#22d3ee; --purple:#a78bfa; --red:#fb7185; --yellow:#fbbf24; --green:#34d399; }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; background: radial-gradient(circle at top left, #14213a, var(--bg) 44%); color: var(--text); font-family: Inter, ui-sans-serif, system-ui, sans-serif; }}
    main {{ max-width: 1280px; margin: 0 auto; padding: 34px; }}
    header {{ border: 1px solid var(--line); border-radius: 24px; padding: 28px; background: linear-gradient(135deg, rgba(34,211,238,.14), rgba(167,139,250,.08)); box-shadow: 0 24px 80px rgba(0,0,0,.35); }}
    h1 {{ margin: 0; font-size: clamp(30px, 5vw, 58px); letter-spacing: .08em; text-transform: uppercase; }}
    .subtitle {{ color: var(--muted); margin-top: 8px; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 14px; margin: 22px 0; }}
    .card, .finding, .panel {{ background: rgba(13,24,38,.88); border: 1px solid var(--line); border-radius: 18px; padding: 18px; }}
    .card span {{ display:block; color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .09em; }}
    .card strong {{ display:block; margin-top: 8px; font-size: 18px; color: var(--cyan); word-break: break-word; }}
    .findings {{ display:grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 14px; }}
    .finding h2 {{ margin:0 0 10px; font-size: 16px; }}
    .finding.danger {{ border-color: rgba(251,113,133,.6); }}
    .finding.danger h2 {{ color: var(--red); }}
    .finding.warning {{ border-color: rgba(251,191,36,.55); }}
    .finding.warning h2 {{ color: var(--yellow); }}
    .finding.info h2 {{ color: var(--cyan); }}
    ul {{ margin: 0; padding-left: 20px; }}
    li {{ margin: 7px 0; word-break: break-word; }}
    .muted {{ color: var(--muted); }}
    table {{ width:100%; border-collapse: collapse; overflow:hidden; border-radius: 14px; }}
    th, td {{ text-align:left; padding: 11px 12px; border-bottom: 1px solid rgba(36,65,95,.75); vertical-align: top; }}
    th {{ color: var(--muted); text-transform: uppercase; font-size: 12px; letter-spacing: .08em; background: var(--panel2); }}
    .state {{ padding: 4px 9px; border-radius: 999px; font-size: 12px; font-weight: 700; }}
    .state-ok {{ background: rgba(52,211,153,.16); color: var(--green); }}
    .state-skipped {{ background: rgba(120,144,168,.16); color: var(--muted); }}
    .state-missing, .state-exit {{ background: rgba(251,191,36,.16); color: var(--yellow); }}
    h2.section {{ margin: 30px 0 12px; color: var(--purple); }}
    pre {{ margin: 0; padding: 20px; overflow: auto; line-height: 1.35; font-size: 12px; white-space: pre-wrap; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
  </style>
</head>
<body>
  <main>
    <header>
      <h1>Vegas Recon</h1>
      <div class="subtitle">Generated {html.escape(summary.generated_at)} | Terminal-first report with highlighted AD findings</div>
    </header>
    <section class="grid">{card_html}</section>
    <h2 class="section">High Signal Findings</h2>
    <section class="findings">{''.join(finding_html)}</section>
    <h2 class="section">Service Map</h2>
    <section class="panel"><table><thead><tr><th>Port</th><th>Proto</th><th>Service</th><th>Details</th></tr></thead><tbody>{service_rows}</tbody></table></section>
    <h2 class="section">Module Status</h2>
    <section class="panel"><table><thead><tr><th>State</th><th>Module</th></tr></thead><tbody>{module_rows}</tbody></table></section>
    <h2 class="section">Raw Terminal Report</h2>
    <section class="panel"><pre>{escaped}</pre></section>
  </main>
</body>
</html>
""",
        encoding="utf-8",
    )


def cleanup_intermediate_files(run_dir: Path, keep_logs: bool, keep_files: set[str]) -> None:
    if keep_logs:
        return
    for path in run_dir.iterdir():
        if path.is_file() and path.name not in keep_files:
            path.unlink()


def print_summary(summary: ReconSummary) -> None:
    section("Final report")
    detected_ad = "yes" if summary.probable_active_directory else "no"
    ports = ", ".join(str(port) for port in summary.open_ports) or "none"
    domains = ", ".join(summary.domain_names) or "none"
    dc_names = ", ".join(summary.dc_names) or "none"

    ok_count = len([record for record in summary.commands if record.returncode == 0])
    skipped_count = len([record for record in summary.commands if record.returncode == 125])
    missing_count = len([record for record in summary.commands if record.returncode == 127])
    failed_count = len([record for record in summary.commands if record.returncode not in {0, 125, 127}])

    print_table(
        ["Target", "OS", "AD", "Ports", "Domain/DC"],
        [[
            summary.target,
            summary.detected_os,
            detected_ad,
            ports,
            f"{domains} / {dc_names}",
        ]],
        title="Overview",
    )

    print_card(
        "Run metadata",
        [
            ("Requested OS", summary.requested_os),
            ("Generated", summary.generated_at),
            ("Logs", summary.run_directory),
            ("Modules", f"{ok_count} ok, {skipped_count} skipped, {missing_count} missing, {failed_count} failed"),
        ],
    )

    service_rows = [
        [str(entry.port), entry.protocol, entry.service, entry.details or "-"]
        for entry in summary.services[:25]
    ]
    print_table(["Port", "Proto", "Service", "Details"], service_rows, title="Service map")

    subsection("High signal findings")
    print_finding_list("Kerberoastable indicators", summary.findings.get("kerberoastable", []), Style.RED + Style.BOLD, limit=20)
    print_finding_list("ASREP roastable indicators", summary.findings.get("asrep_roastable", []), Style.RED + Style.BOLD, limit=20)
    print_finding_list("Delegation indicators", summary.findings.get("delegation_findings", []), Style.RED + Style.BOLD, limit=20)
    print_finding_list("Privileged group indicators", summary.findings.get("privileged_findings", []), Style.YELLOW + Style.BOLD, limit=20)
    print_finding_list("Services to inspect", summary.findings.get("interesting_services", []), Style.CYAN)
    print_finding_list("Domains", summary.findings.get("domains", []), Style.GREEN + Style.BOLD)
    print_finding_list("Domain controllers / hostnames", summary.findings.get("dc_names", []), Style.GREEN + Style.BOLD)
    print_finding_list("Users", summary.findings.get("users", []), Style.MAGENTA)
    print_finding_list("Non-standard shares", summary.findings.get("nonstandard_shares", []), Style.YELLOW + Style.BOLD)
    print_finding_list("Common shares", summary.findings.get("common_shares", []), Style.GRAY)
    print_finding_list("Interesting files", summary.findings.get("interesting_files", []), Style.YELLOW + Style.BOLD, limit=25)
    print_finding_list("Potential credentials", summary.findings.get("potential_credentials", []), Style.RED + Style.BOLD, limit=20)
    print_finding_list("GPP indicators", summary.findings.get("gpp_findings", []), Style.RED + Style.BOLD, limit=20)
    adcs_findings = summary.findings.get("adcs_findings", [])
    if adcs_findings:
        section("ADCS detected")
        print(color("  Active Directory Certificate Services indicators were found.", Style.RED + Style.BOLD))
        print_finding_list("ADCS evidence", adcs_findings, Style.RED + Style.BOLD, limit=20)
    print_finding_list("Groups", summary.findings.get("groups", []), Style.MAGENTA)
    print_finding_list("Possible vulns", summary.findings.get("possible_vulns", []), Style.RED + Style.BOLD)

    follow_up = build_follow_up(summary)
    if follow_up:
        subsection("Suggested next moves")
        for index, step in enumerate(follow_up, start=1):
            print(f"  {color(str(index) + '.', Style.BOLD)} {step}")

    status_rows = []
    for record in summary.commands:
        state = command_state(record)
        if KEEP_LOGS:
            log_name = Path(record.output_file).name
            status_rows.append([state, record.name, log_name])
        else:
            status_rows.append([state, record.name])
    if KEEP_LOGS:
        print_table(["State", "Module", "Log"], status_rows, title="Module status")
    else:
        print_table(["State", "Module"], status_rows, title="Module status")

    missing_tools = [record.command[0] for record in summary.commands if record.returncode == 127]
    if missing_tools:
        warn("Missing tools: " + ", ".join(ordered_unique(missing_tools)))


def main() -> int:
    global USE_COLOR, KEEP_LOGS
    args = parse_args()
    USE_COLOR = not args.no_color
    KEEP_LOGS = args.keep_logs
    session_id = create_session_id(args.target)
    run_dir = create_run_dir(args.output_root, args.target)
    report_txt = run_dir / f"report_{session_id}.txt"
    report_html = run_dir / f"report_{session_id}.html"
    original_stdout = sys.stdout
    recorder = TerminalRecorder(original_stdout, report_txt)
    sys.stdout = recorder

    print_banner()

    section("Session")
    kv("Target", args.target, Style.CYAN + Style.BOLD)
    kv("Mode", "dry-run" if args.dry_run else "execute", Style.YELLOW if args.dry_run else Style.GREEN + Style.BOLD)
    kv("AD mode", args.ad, status_style(args.ad))

    if not args.dry_run:
        ensure_tool("nmap")

    kv("Output", str(report_txt), Style.GRAY)
    commands: list[CommandRecord] = []

    full_scan_file = run_dir / "nmap_ports.txt"
    service_scan_file = run_dir / "nmap_sVsC.txt"
    vuln_scan_file = run_dir / "nmap_vuln.txt"

    open_ports: list[int] = []
    services: list[ServiceEntry] = []

    if args.skip_full_scan:
        full_scan_file.write_text("[skipped]\n", encoding="utf-8")
    else:
        section("Nmap recon")
        full_scan_command = [
            "nmap",
            "-p-",
            "-Pn",
            args.target,
            "-v",
            "--min-rate",
            str(args.min_rate),
            "--max-rtt-timeout",
            args.max_rtt_timeout,
            "--max-retries",
            str(args.max_retries),
        ]
        commands.append(run_command("Full TCP port scan", full_scan_command, full_scan_file, args.dry_run, args.verbose_output, args.show_commands, args.nmap_timeout))
        open_ports = parse_open_ports(read_text(full_scan_file))

    if args.skip_service_scan:
        service_scan_file.write_text("[skipped]\n", encoding="utf-8")
    else:
        if not open_ports and full_scan_file.exists():
            open_ports = parse_open_ports(read_text(full_scan_file))
        if not open_ports:
            service_scan_file.write_text("No open ports parsed from the first scan.\n", encoding="utf-8")
        else:
            service_scan_command = [
                "nmap",
                "-Pn",
                args.target,
                "-p",
                ",".join(str(port) for port in open_ports),
                "-sV",
                "-sC",
                "-v",
            ]
            commands.append(run_command("Service scan", service_scan_command, service_scan_file, args.dry_run, args.verbose_output, args.show_commands, args.nmap_timeout))
            services = parse_services(read_text(service_scan_file))

    if args.skip_vuln_scan:
        vuln_scan_file.write_text("[skipped]\n", encoding="utf-8")
    elif not open_ports:
        vuln_scan_file.write_text("No open ports parsed from the first scan.\n", encoding="utf-8")
    else:
        vuln_scan_command = [
            "nmap",
            "-T5",
            "-Pn",
            args.target,
            "-v",
            "--script",
            "vuln",
        ]
        commands.append(run_command("Vuln script scan", vuln_scan_command, vuln_scan_file, args.dry_run, args.verbose_output, args.show_commands, args.nmap_timeout))

    combined_text = "\n".join([read_text(full_scan_file), read_text(service_scan_file), read_text(vuln_scan_file)])
    if not open_ports:
        open_ports = parse_open_ports(combined_text)
    if not services:
        services = parse_services(combined_text)

    domain_names = extract_domains(combined_text)
    dc_names = extract_dc_names(combined_text)
    detected_os = detect_os(args.os, open_ports, services, combined_text)
    probable_ad = detect_active_directory(open_ports, combined_text, domain_names)
    if args.ad == "yes":
        probable_ad = True
    elif args.ad == "no":
        probable_ad = False

    if probable_ad and not args.skip_ad_enum:
        dc_ip = args.dc_ip or args.target
        commands.extend(run_ad_flow(args, run_dir, dc_ip, args.dry_run, args.verbose_output, args.show_commands, args.command_timeout))

    findings = extract_findings(run_dir, services, domain_names, dc_names)

    summary = ReconSummary(
        target=args.target,
        requested_os=args.os,
        detected_os=detected_os,
        probable_active_directory=probable_ad,
        open_ports=open_ports,
        services=services,
        domain_names=domain_names,
        dc_names=dc_names,
        run_directory=str(report_txt),
        commands=commands,
        findings=findings,
        generated_at=datetime.now().isoformat(timespec="seconds"),
    )

    write_summary_files(summary, run_dir)
    print_summary(summary)
    recorder.flush()
    sys.stdout = original_stdout
    recorder.close()
    if args.html_report:
        write_html_report(report_txt, report_html, summary)
    keep_files = {report_txt.name}
    if args.html_report:
        keep_files.add(report_html.name)
    cleanup_intermediate_files(run_dir, args.keep_logs, keep_files)
    return 0


if __name__ == "__main__":
    sys.exit(main())
