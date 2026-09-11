# SAP RFM enumeration tool

Find remote function modules (RFMs) an AS ABAP will run **without authentication**, built
on [pysap](https://github.com/OWASP/pysap) — no NetWeaver RFC SDK, no SAP GUI, no
credentials.

## Why it works

An RFC type-3 connection names the function module it wants in the very first CPIC packet,
*before* any logon. The work process decides from that one packet whether to dispatch the
function or demand a logon first. A short list of modules — `RFC_PING`, `RFC_SYSTEM_INFO`,
`SYSTEM_INVISIBLE_GUI` — is answered pre-logon by design; everything else comes back with
kernel error `00024 error during logon`. That difference is the oracle.

The tool sends the SDK's *anonymous* connect (byte-for-byte what the NW RFC SDK emits with
no credentials configured, minus the user/password TLVs) naming each candidate, reads one
reply, and classifies it.

## Files

```
rfm_enum.py            the whole tool — CPIC codec, APPC layer, client and CLI in one file
wordlists/rfm_all.txt  21.7k remote-enabled function-module names (example wordlist)
requirements.txt       just pysap (pulls in scapy)
```

## Install & run

```bash
python3 -m venv .venv && ./.venv/bin/pip install pysap
./.venv/bin/python rfm_enum.py <host>                          # built-in candidate list
./.venv/bin/python rfm_enum.py <host> --all                    # show logon-required too
./.venv/bin/python rfm_enum.py <host> -w wordlists/rfm_all.txt -T 16 -o scan.jsonl
./.venv/bin/python rfm_enum.py <host> -f RFC_PING -f RFC_SYSTEM_INFO
./.venv/bin/python rfm_enum.py <host> --route "/H/router/S/3299/H/target"
./.venv/bin/python rfm_enum.py <host> -u DEVELOPER -w wordlists/rfm_all.txt   # authenticated
```

## Authenticated scan

The default scan is anonymous. Give `-u/--user` (and `-P/--passwd`, or be prompted) and the
tool logs on for each probe, so the results say which modules **that user is authorized to
call** — an S_RFC authorization map for the account. The password is obfuscated on the wire
with pysap's `ab_scramble` (the reversible XOR scheme the NetWeaver RFC SDK uses; this tool
imitates that client, so UTF-16LE encoding).

Verdicts in this mode: `[AUTHZD]` the call ran (logon + S_RFC both passed), `[noauth]` the
logon succeeded but the user lacks S_RFC for that function group, `[LOGON!]` the logon
itself failed.

> **Lockout warning.** Each probe is a real logon. A wrong password across a wordlist is
> thousands of failed logons — enough to lock the account and trip security alerting. The
> tool runs a single preflight logon first and **aborts the whole scan if it fails**, so a
> bad password costs one failed logon, not thousands. Only run authenticated scans against
> systems you are authorized to test.

When exactly one module is probed (`-f NAME`, or a one-line wordlist) and it answers
unauthenticated, its decoded reply is printed in full — the connect-accept echo is stripped
so what shows is the module's own return data:

```
./.venv/bin/python rfm_enum.py <host> -f RFC_GET_LOCAL_SERVERS

[*] RFC_GET_LOCAL_SERVERS (unauthenticated):
      0x0301  HOSTS
      0x0304
        vhcala4hci_A4H_00     vhcala4hci     sapdp00 ...
```

`RFC_SYSTEM_INFO` is decoded into its named RFCSI fields; every other module's values are
dumped as text (hex when they do not decode). Against a lab AS ABAP (kernel 793, gateway on
3300):

```
[*] 3 of 16 callable unauthenticated: RFC_PING, RFC_SYSTEM_INFO, SYSTEM_INVISIBLE_GUI

[*] RFC_SYSTEM_INFO (unauthenticated):
      RFCSYSID    A4H
      RFCDBSYS    HDB
      RFCSAPRL    758
      RFCKERNRL   793
      RFCOPSYS    Linux
      RFCIPADDR   10.20.30.15
      RFCDEST     vhcala4hci_A4H_00
```

## Speed

Each probe needs its own connection — the kernel tears the conversation down after
refusing a logon — so a full sweep is connection-bound, not CPU-bound. `-T/--threads` runs
probes concurrently: the 21.7k list takes ~1.8 h at `-T 1`, ~2 min at `-T 16` (output stays
in wordlist order, results identical across thread counts). A self-updating status line on
stderr shows progress / running unauth count / rate / ETA (terminal only; `--no-progress`
turns it off).

## Report file

`-o/--report FILE` writes one JSON object per probe (JSONL) — verdict, kernel error
code/message, decoded reply values, and the **raw reply bytes as hex** so nothing is lost
for later analysis. `--no-raw` drops the hex.

```jsonc
{"function":"RFC_SYSTEM_INFO","verdict":"unauthenticated","code":null,"message":null,
 "values":[{"tag":"0450","text":"A4H"}, ...],"raw":"06cb0200..."}
{"function":"RFCPING","verdict":"logon_required","code":"00024",
 "message":"error during logon","values":[],"raw":"c6d9c5c5..."}
```

```bash
jq -r 'select(.verdict=="unauthenticated") | .function' scan.jsonl
```

## Wordlist

`wordlists/rfm_all.txt` is one function-module name per line (blank lines and `#` comments
ignored). It was generated from a FUPARAREF interface dump by keeping every distinct
`FUNCNAME` whose `REMOTE_CALL` flag is `R` (remote-enabled), with the kernel RFC built-ins
(`RFC_PING`, `RFCPING`, ...) — which have no ABAP parameter interface and so never appear
in such a dump — seeded in front, so the modules most likely to answer pre-logon are tested
first. Point `-w` at any file in the same format.

## Scope / limits

- Anonymous by default; `-u` adds an authenticated scan using pysap's `ab_scramble` for the
  `0x0117` password field. The anonymous path is fully verified against the lab. The
  authenticated path is verified end-to-end for logon success/failure detection; the
  `[noauth]` (S_RFC-denied) verdict keys on the kernel message text and has not yet been
  confirmed against a live authorization refusal — treat that one label as provisional.
- Reply parsing covers the verdicts that matter (dispatched / logon-required / logon-failed
  / not-authorized) and the `RFC_SYSTEM_INFO` result record. Full parameter/ITAB
  deserialisation for arbitrary functions is not implemented.
- The 80-byte APPC header constants were derived against kernel 7.93; other kernels may
  differ.

Authorized security testing only.
