"""Inventory loading and the peering plan.

The interesting part of a WireGuard mesh isn't writing [Peer] blocks, it's
deciding *who can actually reach whom*:

* two nodes with public endpoints: peer directly
* one public, one behind NAT: peer directly, the NAT'd side dials out and
  needs PersistentKeepalive to hold the NAT mapping open
* both behind NAT: they can't find each other. Traffic has to go through a
  relay (any node with a public endpoint) - which means the relay's
  AllowedIPs on each side must include the other node's address.

AllowedIPs is WireGuard's routing table, so that last case is where
hand-written configs usually go wrong.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

import yaml


class InventoryError(ValueError):
    pass


@dataclass
class Node:
    name: str
    address: ipaddress.IPv4Interface | None = None
    endpoint: str | None = None          # host:port reachable from the internet, or None if behind NAT
    listen_port: int | None = None
    routes: list = field(default_factory=list)   # extra subnets behind this node (site LANs)
    relay: bool = False                  # allowed to forward for others
    dns: list = field(default_factory=list)
    mtu: int | None = None

    @property
    def public(self) -> bool:
        return self.endpoint is not None

    @property
    def ip(self):
        return self.address.ip

    def allowed(self) -> list:
        """Prefixes that live behind this node: its tunnel /32 + any routes."""
        return [ipaddress.ip_network(f"{self.address.ip}/32")] + list(self.routes)


@dataclass
class Inventory:
    network: ipaddress.IPv4Network
    topology: str                        # mesh | hub
    port: int
    keepalive: int
    nodes: list
    hubs: list = field(default_factory=list)
    preshared: bool = True

    def get(self, name):
        for n in self.nodes:
            if n.name == name:
                return n
        raise KeyError(name)


def load(path_or_text: str, *, is_text: bool = False) -> Inventory:
    if is_text:
        data = yaml.safe_load(path_or_text)
    else:
        with open(path_or_text, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise InventoryError("inventory must be a YAML mapping")

    try:
        net = ipaddress.ip_network(str(data["network"]), strict=True)
    except KeyError:
        raise InventoryError("missing 'network' (e.g. network: 10.77.0.0/24)") from None
    except ValueError as e:
        raise InventoryError(f"network: {e}") from None
    if net.version != 4:
        raise InventoryError("only IPv4 tunnel networks for now")

    topology = data.get("topology", "mesh")
    if topology not in ("mesh", "hub"):
        raise InventoryError("topology must be 'mesh' or 'hub'")
    port = int(data.get("port", 51820))
    keepalive = int(data.get("keepalive", 25))

    raw_nodes = data.get("nodes") or {}
    if isinstance(raw_nodes, list):
        # allow a list of {name: ...} too
        raw_nodes = {n["name"]: n for n in raw_nodes}
    if not raw_nodes:
        raise InventoryError("no nodes")

    nodes = []
    for name, nd in raw_nodes.items():
        nd = nd or {}
        node = Node(name=str(name))
        if "address" in nd:
            ip = ipaddress.ip_address(str(nd["address"]).split("/")[0])
            if ip not in net:
                raise InventoryError(f"{name}: address {ip} is outside {net}")
            node.address = ipaddress.ip_interface(f"{ip}/{net.prefixlen}")
        ep = nd.get("endpoint")
        if ep:
            ep = str(ep)
            if ":" not in ep.rsplit("]", 1)[-1]:
                ep = f"{ep}:{nd.get('listen_port', port)}"
            node.endpoint = ep
        node.listen_port = int(nd.get("listen_port", port)) if node.endpoint or nd.get("listen_port") else None
        for r in nd.get("routes", []) or []:
            try:
                node.routes.append(ipaddress.ip_network(str(r), strict=True))
            except ValueError as e:
                raise InventoryError(f"{name}: route {r}: {e}") from None
        node.relay = bool(nd.get("relay", node.public))
        node.dns = [str(x) for x in nd.get("dns", []) or []]
        node.mtu = nd.get("mtu")
        nodes.append(node)

    _assign_addresses(net, nodes)

    hubs = data.get("hubs") or []
    if topology == "hub":
        if not hubs:
            hubs = [n.name for n in nodes if n.public][:1]
        if not hubs:
            raise InventoryError("hub topology needs at least one node with an endpoint")
    for h in hubs:
        if h not in raw_nodes:
            raise InventoryError(f"hub {h!r} isn't a node")

    return Inventory(network=net, topology=topology, port=port, keepalive=keepalive,
                     nodes=nodes, hubs=list(hubs), preshared=bool(data.get("preshared_keys", True)))


def _assign_addresses(net, nodes):
    """Give every node without an explicit address the next free one.

    Explicit addresses win; the rest are handed out in inventory order,
    skipping network/broadcast. Same inventory -> same addresses.
    """
    used = {}
    for n in nodes:
        if n.address:
            if n.address.ip in used:
                raise InventoryError(f"{n.name} and {used[n.address.ip]} both use {n.address.ip}")
            used[n.address.ip] = n.name
    free = (ip for ip in net.hosts() if ip not in used)
    for n in nodes:
        if not n.address:
            try:
                ip = next(free)
            except StopIteration:
                raise InventoryError(f"{net} is full") from None
            n.address = ipaddress.ip_interface(f"{ip}/{net.prefixlen}")
            used[ip] = n.name


@dataclass
class Link:
    a: str
    b: str
    kind: str            # direct | relayed
    via: str | None = None


def plan(inv: Inventory) -> list:
    """Return the list of tunnels to build."""
    links = []
    nodes = inv.nodes
    if inv.topology == "hub":
        hubs = [inv.get(h) for h in inv.hubs]
        for h in hubs:
            for n in nodes:
                if n.name not in inv.hubs:
                    links.append(Link(h.name, n.name, "direct"))
        # hubs peer with each other so spokes on different hubs can talk
        for i, a in enumerate(hubs):
            for b in hubs[i + 1:]:
                links.append(Link(a.name, b.name, "direct"))
        return links

    relays = [n for n in nodes if n.relay and n.public]
    for i, a in enumerate(nodes):
        for b in nodes[i + 1:]:
            if a.public or b.public:
                links.append(Link(a.name, b.name, "direct"))
            elif relays:
                links.append(Link(a.name, b.name, "relayed", via=relays[0].name))
            else:
                links.append(Link(a.name, b.name, "unreachable"))
    return links
