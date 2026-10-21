"""Native saarCTF checker for INQ Terminal's two flag stores."""
from __future__ import annotations

import base64
import hashlib
import socket

from gamelib import (FlagMissingException, MumbleException, OfflineException,
                     ServiceInterface, Team)

PORT = 9423
TIMEOUT = 5
MAX_RESPONSE = 1 << 20
MAX_ROWS = 4096


class TerminalConnection:
    def __init__(self, host: str) -> None:
        try:
            self.socket = socket.create_connection((host, PORT), timeout=TIMEOUT)
            self.socket.settimeout(TIMEOUT)
        except OSError as exc:
            raise OfflineException(f"INQ Terminal is unreachable: {exc}") from exc
        self.buffer = b""

    def close(self) -> None:
        try:
            self.socket.close()
        except OSError:
            pass

    def _readline(self) -> str:
        while b"\n" not in self.buffer:
            if len(self.buffer) > MAX_RESPONSE:
                raise MumbleException("terminal sent an unterminated response")
            try:
                chunk = self.socket.recv(65536)
            except socket.timeout as exc:
                raise OfflineException("terminal timed out mid-response") from exc
            except OSError as exc:
                raise OfflineException(f"terminal connection failed: {exc}") from exc
            if not chunk:
                raise OfflineException("terminal closed the connection mid-response")
            self.buffer += chunk
        line, self.buffer = self.buffer.split(b"\n", 1)
        return line.decode("utf-8", "replace").rstrip("\r")

    def command(self, line: str, allow_error: bool = False) -> str | None:
        try:
            self.socket.sendall((line + "\n").encode())
        except OSError as exc:
            raise OfflineException(f"could not send {line.split()[0]}: {exc}") from exc
        answer = self._readline()
        if answer.startswith("ERR"):
            if allow_error:
                return None
            raise MumbleException(f"{line.split()[0]} was rejected: {answer[:160]}")
        if not answer.startswith("OK"):
            raise MumbleException(f"{line.split()[0]} returned a malformed response")
        return answer[2:].strip()

    def rows(self, line: str) -> tuple[str, list[str]]:
        head = self.command(line)
        rows: list[str] = []
        while True:
            row = self._readline()
            if row == ".":
                return head or "", rows
            rows.append(row)
            if len(rows) > MAX_ROWS:
                raise MumbleException("terminal row response never terminated")


class INQTerminalService(ServiceInterface):
    name = "INQ Terminal"
    num_stores = 2

    def _seed(self, team: Team, tick: int, place: int, role: str = "flag") -> str:
        material = f"inq-terminal|{self.id}|{team.id}|{tick}|{place}|{role}"
        return hashlib.sha256(material.encode()).hexdigest()

    def _credentials(self, team: Team, tick: int, place: int,
                     role: str = "flag") -> tuple[str, str]:
        seed = self._seed(team, tick, place, role)
        return f"ctf{seed[:15]}", seed[16:48]

    def _label(self, team: Team, tick: int, place: int) -> str:
        return "slip" + self._seed(team, tick, place)[:20]

    @staticmethod
    def _encode(value: str) -> str:
        return base64.b64encode(value.encode()).decode()

    @staticmethod
    def _decode(value: str | None, operation: str) -> str:
        try:
            if value is None:
                raise ValueError("missing value")
            return base64.b64decode(value, validate=True).decode()
        except (ValueError, UnicodeDecodeError) as exc:
            raise MumbleException(f"{operation} returned invalid base64") from exc

    def _login(self, connection: TerminalConnection, team: Team, tick: int,
               place: int, create: bool, role: str = "flag") -> str:
        username, password = self._credentials(team, tick, place, role)
        if create:
            token = connection.command(f"REG {username} {password}", allow_error=True)
            if token:
                return token
        token = connection.command(f"AUTH {username} {password}", allow_error=not create)
        if token is None:
            raise FlagMissingException("the account holding a terminal flag is missing")
        return token

    @staticmethod
    def _find_slip(connection: TerminalConnection, token: str,
                   label: str) -> str | None:
        _, rows = connection.rows(f"LIST {token}")
        for row in rows:
            parts = row.split(" ", 1)
            if len(parts) == 2 and parts[1] == label:
                return parts[0]
        return None

    def check_integrity(self, team: Team, tick: int) -> None:
        connection = TerminalConnection(team.ip)
        try:
            greeting = connection.command("HELLO")
            if greeting != "terminal/1 [ INQ // SELF-SERVICE TERMINAL ]":
                raise MumbleException("terminal greeting is malformed")
            status = connection.command("STAT") or ""
            if not status.startswith("users=") or " slips=" not in status:
                raise MumbleException("terminal status is malformed")
            connection.command("WHO")
            _, rows = connection.rows("MANIFEST")
            for row in rows[:20]:
                if len(row.split()) != 5:
                    raise MumbleException("terminal manifest contains a malformed row")

            username, password = self._credentials(team, tick, 0, "integrity")
            token = connection.command(f"REG {username} {password}", allow_error=True)
            if token is None:
                token = connection.command(f"AUTH {username} {password}")
            if connection.command(f"AUTH {username} {password}") != token:
                raise MumbleException("terminal authentication is inconsistent")
            if connection.command(
                    f"AUTH {username} {password}x", allow_error=True) is not None:
                raise MumbleException("terminal accepted an invalid password")
        finally:
            connection.close()

    def store_flags(self, team: Team, tick: int) -> None:
        connection = TerminalConnection(team.ip)
        try:
            for place in range(self.num_stores):
                flag = self.get_flag(team, tick, place)
                token = self._login(connection, team, tick, place, create=True)
                label = self._label(team, tick, place)
                slip = self._find_slip(connection, token, label)
                if slip is None:
                    slip = connection.command(f"NEW {token} {label}")
                if not slip:
                    raise MumbleException(f"terminal did not create flag store {place}")
                write = "NOTE" if place == 0 else "SEAL"
                read = "READNOTE" if place == 0 else "READPIN"
                connection.command(f"{write} {token} {slip} {self._encode(flag)}")
                stored = self._decode(
                    connection.command(f"{read} {token} {slip}"), read
                )
                if stored != flag:
                    raise MumbleException(f"terminal flag store {place} altered the flag")
        finally:
            connection.close()

    def retrieve_flags(self, team: Team, tick: int) -> None:
        connection = TerminalConnection(team.ip)
        try:
            for place in range(self.num_stores):
                expected = self.get_flag(team, tick, place)
                token = self._login(connection, team, tick, place, create=False)
                slip = self._find_slip(connection, token, self._label(team, tick, place))
                if slip is None:
                    raise FlagMissingException(f"terminal flag store {place} is missing")
                read = "READNOTE" if place == 0 else "READPIN"
                stored = self._decode(
                    connection.command(f"{read} {token} {slip}"), read
                )
                if stored != expected:
                    raise FlagMissingException(
                        f"terminal flag store {place} no longer contains its flag"
                    )
        finally:
            connection.close()
