"""
Checker for the FlagPage service.

Each tick the gameserver calls store_flags (plant a flag on the team's box),
then later retrieve_flags (read it back) and check_integrity (service alive).
Reaches the team's vulnbox at team.ip:9100.
"""
import requests
from gamelib import (ServiceInterface, Team, OfflineException, MumbleException,
                     FlagMissingException)

PORT = 9100
TIMEOUT = 5


class FlagPageService(ServiceInterface):
    name = "FlagPage"

    def _url(self, team: Team) -> str:
        return f"http://{team.ip}:{PORT}/"

    def check_integrity(self, team: Team, tick: int) -> None:
        try:
            r = requests.get(self._url(team), timeout=TIMEOUT)
        except requests.exceptions.RequestException:
            raise OfflineException("FlagPage is not reachable")
        if r.status_code != 200:
            raise MumbleException(f"unexpected status {r.status_code}")

    def store_flags(self, team: Team, tick: int) -> None:
        flag = self.get_flag(team, tick, 0)
        try:
            r = requests.post(self._url(team),
                              data={"tick": tick, "flag": flag}, timeout=TIMEOUT)
        except requests.exceptions.RequestException:
            raise OfflineException("FlagPage is not reachable")
        if r.status_code != 200:
            raise MumbleException(f"store failed: status {r.status_code}")

    def retrieve_flags(self, team: Team, tick: int) -> None:
        try:
            r = requests.get(self._url(team), params={"tick": tick}, timeout=TIMEOUT)
        except requests.exceptions.RequestException:
            raise OfflineException("FlagPage is not reachable")
        if r.status_code != 200:
            raise MumbleException(f"retrieve failed: status {r.status_code}")
        if not self.search_flags(r.text):
            raise FlagMissingException("flag not present on the page")
