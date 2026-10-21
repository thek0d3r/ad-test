"""Native saarCTF checker for INQ Online's four flag stores."""
from __future__ import annotations

import hashlib
from typing import Any

import requests
from gamelib import (FlagMissingException, MumbleException, OfflineException,
                     ServiceInterface, Team)

PORT = 9421
TIMEOUT = 5


class INQOnlineService(ServiceInterface):
    name = "INQ Online"
    num_stores = 4

    def _url(self, team: Team, path: str) -> str:
        return f"http://{team.ip}:{PORT}{path}"

    def _request(self, team: Team, method: str, path: str, token: str | None = None,
                 **kwargs: Any) -> requests.Response:
        headers = dict(kwargs.pop("headers", {}))
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            return requests.request(method, self._url(team, path), headers=headers,
                                    timeout=TIMEOUT, **kwargs)
        except requests.exceptions.RequestException as exc:
            raise OfflineException(f"INQ Online is unreachable: {exc}") from exc

    @staticmethod
    def _json(response: requests.Response, operation: str) -> dict:
        try:
            body = response.json()
        except ValueError as exc:
            raise MumbleException(f"{operation} returned invalid JSON") from exc
        if not isinstance(body, dict):
            raise MumbleException(f"{operation} returned the wrong JSON type")
        return body

    @staticmethod
    def _expect(response: requests.Response, operation: str, *codes: int) -> None:
        if response.status_code not in codes:
            raise MumbleException(
                f"{operation} returned HTTP {response.status_code}: {response.text[:160]}"
            )

    def _seed(self, team: Team, tick: int, place: int, role: str = "flag") -> str:
        material = f"inq-online|{self.id}|{team.id}|{tick}|{place}|{role}"
        return hashlib.sha256(material.encode()).hexdigest()

    def _credentials(self, team: Team, tick: int, place: int, role: str = "flag") -> tuple[str, str]:
        seed = self._seed(team, tick, place, role)
        return f"ctf-{seed[:16]}", seed[16:56]

    def _login(self, team: Team, tick: int, place: int, create: bool,
               role: str = "flag") -> str:
        username, password = self._credentials(team, tick, place, role)
        if create:
            response = self._request(
                team, "POST", "/api/register",
                json={"username": username, "password": password},
            )
            if response.status_code == 201:
                token = self._json(response, "register").get("token")
                if isinstance(token, str) and token:
                    return token
            elif response.status_code != 409:
                self._expect(response, "register", 201, 409)

        response = self._request(
            team, "POST", "/api/login",
            json={"username": username, "password": password},
        )
        if not create and response.status_code == 401:
            raise FlagMissingException("the account holding a flag is missing")
        self._expect(response, "login", 200)
        token = self._json(response, "login").get("token")
        if not isinstance(token, str) or not token:
            raise MumbleException("login did not return a token")
        return token

    def _beneficiary(self, team: Team, tick: int, place: int) -> str:
        seed = self._seed(team, tick, place)
        return "RO49INQB" + seed[:16].translate(str.maketrans("abcdef", "012345"))

    def _label(self, team: Team, tick: int, place: int) -> str:
        return "ctf-" + self._seed(team, tick, place)[:20]

    def _find_transfer(self, team: Team, token: str, beneficiary: str) -> str | None:
        response = self._request(team, "GET", "/api/transfers", token)
        self._expect(response, "list transfers", 200)
        rows = self._json(response, "list transfers").get("transfers")
        if not isinstance(rows, list):
            raise MumbleException("transfer listing is malformed")
        for row in rows:
            if isinstance(row, dict) and row.get("beneficiary") == beneficiary:
                return str(row.get("id"))
        return None

    def _ensure_transfer(self, team: Team, token: str, beneficiary: str,
                         memo: str) -> str:
        transfer_id = self._find_transfer(team, token, beneficiary)
        if transfer_id:
            return transfer_id
        response = self._request(
            team, "POST", "/api/transfers", token,
            json={"beneficiary": beneficiary, "amount": "42.50", "memo": memo},
        )
        self._expect(response, "create transfer", 201)
        transfer_id = self._json(response, "create transfer").get("id")
        if not isinstance(transfer_id, str):
            raise MumbleException("create transfer omitted its id")
        return transfer_id

    def _find_mandate(self, team: Team, token: str, transfer_id: str) -> str | None:
        response = self._request(team, "GET", "/api/mandates", token)
        self._expect(response, "list mandates", 200)
        rows = self._json(response, "list mandates").get("mandates")
        if not isinstance(rows, list):
            raise MumbleException("mandate listing is malformed")
        for row in rows:
            if isinstance(row, dict) and row.get("transfer_id") == transfer_id:
                return str(row.get("id"))
        return None

    def _find_order(self, team: Team, token: str, label: str) -> str | None:
        response = self._request(team, "GET", "/api/orders", token)
        self._expect(response, "list orders", 200)
        rows = self._json(response, "list orders").get("orders")
        if not isinstance(rows, list):
            raise MumbleException("order listing is malformed")
        for row in rows:
            if isinstance(row, dict) and row.get("label") == label:
                return str(row.get("id"))
        return None

    def _read_vault(self, team: Team, token: str, order_id: str) -> str:
        response = self._request(team, "POST", f"/api/orders/{order_id}/authorize", token)
        self._expect(response, "authorize order", 200)
        ticket = self._json(response, "authorize order").get("ticket")
        if not isinstance(ticket, str):
            raise MumbleException("authorize order omitted its ticket")
        response = self._request(
            team, "GET", f"/api/vault/{order_id}", params={"ticket": ticket}
        )
        self._expect(response, "read vault", 200)
        return str(self._json(response, "read vault").get("vault") or "")

    def check_integrity(self, team: Team, tick: int) -> None:
        response = self._request(team, "GET", "/health")
        self._expect(response, "health", 200)
        health = self._json(response, "health")
        if health.get("service") != "webcrypto" or health.get("status") != "ok":
            raise MumbleException("health response does not identify a healthy INQ Online")
        response = self._request(team, "GET", "/")
        self._expect(response, "front page", 200)
        if "INQ" not in response.text:
            raise MumbleException("the INQ Online front page is missing")
        for path, key in (("/api/feed", "transfers"), ("/api/registry", "orders")):
            response = self._request(team, "GET", path)
            self._expect(response, path, 200)
            if not isinstance(self._json(response, path).get(key), list):
                raise MumbleException(f"{path} returned a malformed listing")

    def store_flags(self, team: Team, tick: int) -> None:
        for place in range(self.num_stores):
            flag = self.get_flag(team, tick, place)
            token = self._login(team, tick, place, create=True)
            if place == 0:
                transfer_id = self._ensure_transfer(
                    team, token, self._beneficiary(team, tick, place), flag
                )
                response = self._request(team, "GET", f"/api/transfers/{transfer_id}", token)
                self._expect(response, "read transfer", 200)
                stored = str(self._json(response, "read transfer").get("memo") or "")
            elif place == 1:
                transfer_id = self._ensure_transfer(
                    team, token, self._beneficiary(team, tick, place), "mandate carrier"
                )
                mandate_id = self._find_mandate(team, token, transfer_id)
                if mandate_id is None:
                    response = self._request(
                        team, "POST", "/api/mandates", token,
                        json={"transfer_id": transfer_id, "secret": flag},
                    )
                    self._expect(response, "create mandate", 201)
                    mandate_id = str(self._json(response, "create mandate").get("mandate_id"))
                response = self._request(team, "GET", f"/api/mandates/{mandate_id}", token)
                self._expect(response, "read mandate", 200)
                stored = str(self._json(response, "read mandate").get("secret") or "")
            else:
                label = self._label(team, tick, place)
                order_id = self._find_order(team, token, label)
                if order_id is None:
                    body = ({"label": label, "secret": flag, "vault": "-"} if place == 2
                            else {"label": label, "secret": "-", "vault": flag})
                    response = self._request(team, "POST", "/api/orders", token, json=body)
                    self._expect(response, "create order", 201)
                    order_id = str(self._json(response, "create order").get("id"))
                if place == 2:
                    response = self._request(team, "GET", f"/api/orders/{order_id}/secret", token)
                    self._expect(response, "read order secret", 200)
                    stored = str(self._json(response, "read order secret").get("secret") or "")
                else:
                    stored = self._read_vault(team, token, order_id)
            if stored != flag:
                raise MumbleException(f"flag store {place} did not preserve the flag")

    def retrieve_flags(self, team: Team, tick: int) -> None:
        for place in range(self.num_stores):
            expected = self.get_flag(team, tick, place)
            token = self._login(team, tick, place, create=False)
            if place in (0, 1):
                transfer_id = self._find_transfer(
                    team, token, self._beneficiary(team, tick, place)
                )
                if transfer_id is None:
                    raise FlagMissingException(f"flag store {place} transfer is missing")
                if place == 0:
                    response = self._request(team, "GET", f"/api/transfers/{transfer_id}", token)
                    self._expect(response, "read transfer", 200)
                    stored = str(self._json(response, "read transfer").get("memo") or "")
                else:
                    mandate_id = self._find_mandate(team, token, transfer_id)
                    if mandate_id is None:
                        raise FlagMissingException("the flag mandate is missing")
                    response = self._request(team, "GET", f"/api/mandates/{mandate_id}", token)
                    self._expect(response, "read mandate", 200)
                    stored = str(self._json(response, "read mandate").get("secret") or "")
            else:
                order_id = self._find_order(team, token, self._label(team, tick, place))
                if order_id is None:
                    raise FlagMissingException(f"flag store {place} order is missing")
                if place == 2:
                    response = self._request(team, "GET", f"/api/orders/{order_id}/secret", token)
                    self._expect(response, "read order secret", 200)
                    stored = str(self._json(response, "read order secret").get("secret") or "")
                else:
                    stored = self._read_vault(team, token, order_id)
            if stored != expected:
                raise FlagMissingException(f"flag store {place} no longer contains its flag")
