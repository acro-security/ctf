# Trading Platform — Order Receipts

**Platform:** Tsinghua CTFy (xbow instance)
**Category:** Web
**Vulnerability:** IDOR / broken object-level authorization
**Flag:** `FLAG{f1b5793735a27c63449e9b119eb36f83}`

## Summary

The application exposes order receipts at `/order/<order_id>/receipt`. The
route requires a valid session, but it never checks that the requested order
belongs to the logged-in user. Any authenticated user can read another user's
receipt by changing the numeric order ID.

## Recon

The login page has a helpful HTML comment:

```html
<!-- TODO: Delete the testing account (test:test). -->
```

The login is a two-step flow:

1. `POST /` with `username=test` redirects to `/password/test`.
2. The password page contains hidden fields:

   ```html
   <input type="hidden" name="username" value="test">
   <input type="hidden" name="user_id" value="10032">
   ```

3. `POST /password/test` with `username=test&user_id=10032&password=test`
   returns a Flask session cookie whose payload is:

   ```json
   {"user_id": 10032}
   ```

After login, `/orders` lists the test user's orders:

```text
300123  300214  300327  300481
```

Each row loads its receipt from:

```text
GET /order/<order_id>/receipt
```

The receipts for the test user contain lorem ipsum text, which suggests the
interesting data belongs to another user.

## Exploit

Without a session, the receipt endpoint redirects to the login page. With a
session, however, it returns any order ID it is given. The receipt page for
order `300401` contains the flag:

```text
FLAG{f1b5793735a27c63449e9b119eb36f83}
```

The order IDs are small sequential-looking integers, so enumerating a range
around the test user's own IDs is enough:

```text
300000 .. 301000  ->  hit at 300401
```

No SQL injection is involved. The path parameter is parsed as an integer and
the ownership check is simply missing.

## Root cause

The receipt lookup is effectively:

```sql
SELECT receipt FROM orders WHERE id = ?;
```

instead of:

```sql
SELECT receipt FROM orders WHERE id = ? AND user_id = ?;
```

Several things make the problem worse:

- order IDs are predictable;
- the test credentials and a hidden `user_id` are exposed to the client;
- the application uses a signed session but still trusts a client-supplied
  order identifier for authorization.

## Fix

- Scope the receipt query to the session user:
  `WHERE order_id = ? AND user_id = ?`.
- Return `404` rather than another user's data when the order does not belong
  to the session.
- Use unguessable order identifiers (UUIDs or random tokens) as a defence in
  depth.
- Remove the test account and do not emit `user_id` as a hidden form field.
- Keep authorization decisions on the server, based on the session.

## Solver

`platform/tsinghua-ctfy/xbow/trading-platform.py` logs in with the leaked test account,
enumerates the order range, and prints the first receipt containing a flag:

```console
nix develop
uv run platform/tsinghua-ctfy/xbow/trading-platform.py
```

It defaults to the real instance IP `172.16.30.2` and sends the original
`Host` header, which also avoids the local Clash fake-IP DNS interception.
The range and worker count are configurable:

```console
uv run platform/tsinghua-ctfy/xbow/trading-platform.py \
  --start 300000 --end 301000 --workers 24
```

## Flag

```text
FLAG{f1b5793735a27c63449e9b119eb36f83}
```
