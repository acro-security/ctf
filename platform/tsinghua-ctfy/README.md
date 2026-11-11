# Tsinghua CTFy

## WireGuard tunnel

The tunnel configuration contains a private key, so it must stay out of Git.
This repository already ignores `attachments/` and any `ctfy-*.conf` or
`*.wg.conf` file.

On macOS or Windows, import the configuration into the official WireGuard
application instead of running `wg-quick` from a terminal; a terminal-started
tunnel can leave a stale interface and make the next connection fail silently.

The Nix dev shell provides `wg`, `wg-quick`, `ip`, `iptables`, `resolvconf`,
and `sysctl`. Enter it first:

```console
nix develop
```

### Bring the tunnel up

`wg-quick` needs root. Passing the dev-shell `PATH` through `sudo` is
important: otherwise sudo cannot find `wg`, `ip`, `iptables`, and
`resolvconf`.

```console
sudo env PATH="$PATH" "$(command -v wg-quick)" up \
  platform/tsinghua-ctfy/xbow/attachments/ctfy-63c6ff626b.conf
```

Or use the `just` recipe:

```console
just wg-up platform/tsinghua-ctfy/xbow/attachments/ctfy-63c6ff626b.conf
```

Check the tunnel:

```console
just wg-show
ip address show ctfy-63c6ff626b
```

The interface name comes from the config filename. The tunnel address is
`172.16.30.254/32`.

### DNS

The config sets:

```ini
DNS = 172.16.30.3, 1.1.1.1, 8.8.8.8
```

On Linux, `wg-quick` passes this to `resolvconf`, so the internal `ctfy`
names resolve while the tunnel is up. On NixOS this temporarily rewrites
`/etc/resolv.conf`; taking the tunnel down restores it.

If DNS does not switch, check that `resolvconf` is on the `PATH` inside sudo:

```console
sudo env PATH="$PATH" sh -c 'command -v resolvconf'
```

With `systemd-resolved` instead, the equivalent manual step is:

```console
sudo resolvectl dns ctfy-63c6ff626b 172.16.30.3 1.1.1.1 8.8.8.8
```

### Clash/Mihomo fake-IP interference

If Clash Verge or another Mihomo-based proxy is running in TUN mode, it may
hijack DNS for `.internal` and return a fake address in `198.18.0.0/16`.
Requests then go to the fake IP and fail with an empty reply.

Either disable TUN mode temporarily, or tell Clash to bypass `.internal`:

- add `*.internal` to `dns.fake-ip-filter`;
- resolve `+.internal` with `172.16.30.3` in `dns.nameserver-policy`;
- add `DOMAIN-SUFFIX,internal,DIRECT` to the rules.

For the `xbow` instance the real address is `172.16.30.2`. A one-off request
that bypasses Clash is:

```console
curl --interface ctfy-63c6ff626b \
  --resolve scdvyr4grj6f3ox7v.internal:80:172.16.30.2 \
  http://scdvyr4grj6f3ox7v.internal/
```

### Callbacks

Challenge instances can reach the tunnel address directly, or use
`ctfy-callback:<port>` to reach the same port on this host.

Listen on the tunnel interface, for example:

```console
nc -lvnp 4444
```

Do not bind only to `127.0.0.1`; the challenge connects from the tunnel side.

Because the DMZ can reach every port on `172.16.30.254`, restrict the
WireGuard interface to the callback ports you are actually using. On NixOS,
add the port declaratively:

```nix
networking.firewall.interfaces."ctfy-63c6ff626b".allowedTCPPorts = [ 4444 ];
```

An imperative equivalent is:

```console
sudo iptables -I INPUT -i ctfy-63c6ff626b -p tcp --dport 4444 -j ACCEPT
sudo iptables -A INPUT -i ctfy-63c6ff626b -j DROP
```

Prefer the declarative NixOS option; the `iptables` commands are only a quick
manual equivalent.

### Tear down

```console
just wg-down platform/tsinghua-ctfy/xbow/attachments/ctfy-63c6ff626b.conf
```

or:

```console
sudo env PATH="$PATH" "$(command -v wg-quick)" down \
  platform/tsinghua-ctfy/xbow/attachments/ctfy-63c6ff626b.conf
```

If the interface is left behind, remove it before reconnecting:

```console
sudo ip link delete ctfy-63c6ff626b
```

## Challenges

- [Trading Platform — Order Receipts](xbow/writeup.md) — IDOR in the order
  receipt endpoint; solver in `xbow/solve.py`.
