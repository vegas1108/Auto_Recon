# Auto Recon

Terminal-first Python recon automation for HTB-style labs and authorized pentest environments.

The project is designed to run inside an Exegol container. Commands are called by their Exegol `PATH` names, for example `nmap`, `netexec`, `smbclient`, `rpcclient`, `ldapsearch`, and `enum4linux-ng`.

Auto Recon runs a practical Nmap-first workflow, detects Windows/Linux and Active Directory indicators, launches conditional AD enumeration modules, highlights high-signal findings, and writes clean final reports.

## Features

- Clean terminal dashboard output with concise module status
- Full TCP Nmap scan, service detection, default scripts, and vuln scripts
- Windows/Linux heuristic detection from ports and service banners
- Active Directory detection from SMB, Kerberos, LDAP, DNS, and related indicators
- Conditional AD workflow with anonymous and authenticated checks
- `enum4linux-ng`, `rpcclient`, `netexec`, `smbclient`, `ldapsearch`, DNS SRV, GPP and share checks
- Smart de-duplication: equivalent user/share/group modules are skipped once useful data is already found
- Non-standard SMB share highlighting
- Lightweight recursive listing of non-standard shares without downloading files
- Interesting file detection and categorization
- Potential credential and GPP indicator highlighting
- ADCS / Certificate Services detection
- Kerberoastable, ASREP roastable, delegation, and privileged group indicators
- Quiet by default: raw tool output is parsed but not printed live
- Final `TXT` report by default, optional styled `HTML` report

## Requirements

Recommended environment:

- Exegol with the usual offensive tooling available in `PATH`

Required:

- Python 3.10+
- `nmap`

Optional tools used when available:

- `enum4linux-ng`
- `rpcclient`
- `netexec`
- `smbclient`
- `ldapsearch`
- `dig`
- `lookupsid.py`
- `kerbrute`
- `ldapdomaindump`
- `adidnsdump`

Missing optional tools do not stop the run. They are marked as `missing` in the final module status.

## Exegol Usage

Run the tool from inside your Exegol workspace:

```bash
python3 recon.py 10.10.11.10 --ad yes --domain fluffy.htb
```

The script does not hardcode tool locations. It expects Exegol tools to be callable directly from the shell, matching the standard Exegol environment:

```bash
nmap
netexec
smbclient
rpcclient
ldapsearch
```

If a tool is not present in the container, the module is skipped and reported as `missing`.

## Quick Start

```bash
python3 recon.py 10.10.11.10
```

Force AD mode:

```bash
python3 recon.py 10.10.11.10 --ad yes --domain fluffy.htb --dc-ip 10.10.11.10
```

Run with credentials:

```bash
python3 recon.py 10.10.11.10 --ad yes --domain fluffy.htb -u 'j.smith' -p 'Password123!'
```

Generate an HTML report:

```bash
python3 recon.py 10.10.11.10 --ad yes --domain fluffy.htb --html-report
```

Fast mode:

```bash
python3 recon.py 10.10.11.10 --ad yes --domain fluffy.htb --fast
```

## Nmap Workflow

The script runs the following Nmap flow without fixed sleeps between commands:

```bash
nmap -p- -Pn <target> -v --min-rate 1000 --max-rtt-timeout 1000ms --max-retries 5
nmap -Pn <target> -p <open_ports> -sV -sC -v
nmap -T5 -Pn <target> -v --script vuln
```

If no open ports are parsed from the first scan, follow-up service and vuln scans are skipped where appropriate.

## Active Directory Workflow

When AD is detected or forced with `--ad yes`, the tool runs relevant AD modules.

Without credentials, it attempts anonymous/null-session checks such as:

- SMB banner and share checks
- RPC null user enumeration
- enum4linux-ng enumeration
- RID lookup checks
- LDAP anonymous checks
- DNS SRV DC discovery when a domain is provided

With credentials, it also runs authenticated checks such as:

- RPC authenticated `enumdomusers`, `querydispinfo`, and `enumdomgroups`
- SMB authenticated share listing
- NetExec users, groups, shares, logged-on users
- GPP password and autologin modules
- LDAP description checks
- LDAP domain dump and ADIDNS dump when relevant tools are present

## Reporting

By default, each run writes one report file directly in the output directory:

```text
report_<target>_<timestamp>.txt
```

With `--html-report`, it also writes:

```text
report_<target>_<timestamp>.html
```

Intermediate command logs are used for parsing and deleted by default. Keep them with:

```bash
python3 recon.py 10.10.11.10 --keep-logs
```

The final report highlights:

- detected OS and AD status
- open ports and service map
- domains and DC names
- users and groups
- non-standard shares
- interesting files in non-standard shares
- potential credentials
- GPP findings
- ADCS evidence
- Kerberoastable and ASREP roastable indicators
- delegation indicators
- privileged group indicators
- module status and skipped/missing/failed commands

## Output Modes

Show commands before execution:

```bash
python3 recon.py 10.10.11.10 --show-commands
```

Print raw tool output live:

```bash
python3 recon.py 10.10.11.10 --verbose-output
```

Disable colors:

```bash
python3 recon.py 10.10.11.10 --no-color
```

Dry-run without executing commands:

```bash
python3 recon.py 10.10.11.10 --ad yes --domain fluffy.htb --dry-run
```

## Useful Options

```text
--os auto|windows|linux      Expected host family, default auto
--ad auto|yes|no             Force or disable AD workflow
--domain DOMAIN              AD domain, for example fluffy.htb
--dc-ip IP                   Domain controller IP, defaults to target
-u, --username USER          Username for authenticated checks
-p, --password PASS          Password for authenticated checks
--user-wordlist FILE         User wordlist for Kerberos enum or spray mode
--share SHARE                Share to test with smbclient, default SYSVOL
--fast                       Skip slower AD modules
--keep-logs                  Keep raw command logs
--html-report                Generate a styled HTML report
--command-timeout SECONDS    Timeout for enum commands, default 120
--nmap-timeout SECONDS       Timeout for Nmap commands, default 900
--vuln-timing T0-T5          Nmap timing profile for vuln scan, default T4
```

## Password Spray

Spray mode is never enabled by default. It requires explicit opt-in:

```bash
python3 recon.py 10.10.11.10 \
  --ad yes \
  --domain fluffy.htb \
  --user-wordlist users.txt \
  --enable-spray \
  --spray-password 'Password123!'
```

You can tune protocols and safety limits:

```bash
python3 recon.py 10.10.11.10 \
  --ad yes \
  --domain fluffy.htb \
  --user-wordlist users.txt \
  --enable-spray \
  --spray-password 'Password123!' \
  --spray-protocols smb,winrm \
  --auth-fail-limit 3 \
  --spray-delay 5
```

## Safety Notes

Use this tool only on systems you own or are explicitly authorized to test, such as HTB labs or approved pentest scopes.

The script automates enumeration and reporting. Review the generated commands and outputs, especially when using credentials or spray mode.

## Project Files

```text
recon.py     Main CLI tool
README.md    Project documentation
```
