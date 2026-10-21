# INQ Online

INQ Bank's HTTP attack/defense service combines an online-banking portal with
an e-signing workflow.

| Property | Value |
|---|---|
| Port | `9421/tcp` |
| Stack | Flask, gunicorn, SQLite |
| Checker | native saarCTF `ServiceInterface` |
| Flag stores | 4 |

## Flag stores

| Store | Value | Legitimate read path |
|---:|---|---|
| 0 | transfer memo | authenticated `GET /api/transfers/<id>` |
| 1 | mandate secret | authenticated `GET /api/mandates/<id>` |
| 2 | order secret | authenticated `GET /api/orders/<id>/secret` |
| 3 | order vault | authorize, then `GET /api/vault/<id>` |

The public feed and registry are discovery surfaces. The intentionally
vulnerable routes and reference attacks are documented in
[`exploits/WRITEUP.md`](exploits/WRITEUP.md).

## Local service

```bash
cd service
docker compose up -d --build
curl http://127.0.0.1:9421/health
```

Run the native checker smoke test from the repository root:

```bash
python3 tests/smoke_checkers.py inq-online 127.0.0.1
```

For game deployment, point the CTF@AC admin panel at this repository, or run
`deploy-challenges.yml` with `challenge_repo_dir` set to its absolute path.
