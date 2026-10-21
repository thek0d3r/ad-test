# INQ Terminal

INQ Bank's binary-exploitation service is a C daemon with a newline-delimited
TCP protocol. It models a self-service terminal with private notes and sealed
PINs.

| Property | Value |
|---|---|
| Port | `9423/tcp` |
| Stack | C, `poll()`, libseccomp |
| Checker | native saarCTF `ServiceInterface` |
| Flag stores | 2 |

## Flag stores

| Store | Value | Legitimate read path |
|---:|---|---|
| 0 | slip note | authenticated `READNOTE` |
| 1 | sealed PIN | authenticated `READPIN` |

The public `WHO` and `MANIFEST` commands are discovery surfaces. The allocator
uses region offsets, keeping the intended memory-disclosure attacks stable
across ASLR and libc versions. Seccomp blocks process creation and execution;
the intended bugs are information leaks, not code execution.

Protocol details, vulnerabilities, and reference attacks are documented in
[`exploits/WRITEUP.md`](exploits/WRITEUP.md).

## Local service

```bash
cd service
docker compose up -d --build
printf 'HELLO\n' | nc 127.0.0.1 9423
```

Run the native checker smoke test from the repository root:

```bash
python3 tests/smoke_checkers.py inq-terminal 127.0.0.1
```

For game deployment, point the CTF@AC admin panel at this repository, or run
`deploy-challenges.yml` with `challenge_repo_dir` set to its absolute path.
