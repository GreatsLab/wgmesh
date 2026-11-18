"""wgmesh - WireGuard mesh / hub-and-spoke configs from one YAML file."""
from __future__ import annotations

import argparse
import ipaddress
import os
import sys

from . import __version__
from .model import InventoryError, load, plan
from .render import KeyStore, render_node


def keys_path(inv_path, override):
    if override:
        return override
    base = os.path.splitext(inv_path)[0]
    return base + ".keys.json"


def check(inv, links) -> list:
    """Return [(level, message)]."""
    out = []
    for l in links:
        if l.kind == "unreachable":
            out.append(("error", f"{l.a} and {l.b} are both behind NAT and there's no relay "
                                 f"(a node with an endpoint) to go through"))
    # every routed prefix must be unique, AllowedIPs can't overlap between peers
    owners = []
    for n in inv.nodes:
        for r in n.routes:
            if r.overlaps(inv.network):
                out.append(("error", f"{n.name}: route {r} overlaps the tunnel network {inv.network}"))
            for other, orr in owners:
                if r.overlaps(orr):
                    out.append(("error", f"{n.name} route {r} overlaps {other} route {orr}"))
            owners.append((n.name, r))
    relayed = [l for l in links if l.kind == "relayed"]
    if relayed:
        via = sorted({l.via for l in relayed})
        out.append(("info", f"{len(relayed)} pair(s) are both behind NAT and go via {', '.join(via)}. "
                            f"Their traffic takes the long way round"))
    if len(inv.nodes) > 2 and not any(n.public for n in inv.nodes):
        out.append(("error", "no node has an endpoint - nothing can connect to anything"))
    for n in inv.nodes:
        if n.public and n.endpoint.split(":")[0].startswith(("10.", "192.168.", "172.")):
            out.append(("warn", f"{n.name}: endpoint {n.endpoint} is a private address. Fine on a LAN, "
                                f"unreachable from outside"))
    return out


def cmd_plan(args):
    inv = load(args.inventory)
    links = plan(inv)
    w = max(len(n.name) for n in inv.nodes)
    print(f"network {inv.network}  topology {inv.topology}  {len(inv.nodes)} nodes  {len(links)} tunnels\n")
    print(f"{'node':<{w}}  {'address':<16} {'endpoint':<28} routes")
    for n in inv.nodes:
        print(f"{n.name:<{w}}  {str(n.address.ip):<16} {(n.endpoint or 'behind NAT'):<28} "
              f"{', '.join(map(str, n.routes)) or '-'}")
    print()
    for l in links:
        arrow = {"direct": "<->", "relayed": f"<-({l.via})->", "unreachable": "XX"}[l.kind]
        print(f"  {l.a} {arrow} {l.b}")
    problems = check(inv, links)
    if problems:
        print()
    for level, msg in problems:
        print(f"{level}: {msg}")
    return 1 if any(lv == "error" for lv, _ in problems) else 0


def cmd_build(args):
    inv = load(args.inventory)
    links = plan(inv)
    problems = check(inv, links)
    for level, msg in problems:
        print(f"{level}: {msg}", file=sys.stderr)
    if any(lv == "error" for lv, _ in problems) and not args.force:
        print("not writing configs, fix the errors (or --force)", file=sys.stderr)
        return 1

    ks = KeyStore(keys_path(args.inventory, args.keys))
    ks.prune([n.name for n in inv.nodes])
    os.makedirs(args.out, exist_ok=True)
    for n in inv.nodes:
        conf = render_node(inv, ks, n.name, links)
        path = os.path.join(args.out, f"{args.iface}-{n.name}.conf")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(conf)
        print(f"wrote {path}")
    ks.save()
    print(f"\nkeys in {ks.path} - keep it out of git. Copy each conf to /etc/wireguard/{args.iface}.conf "
          f"on its node and run: wg-quick up {args.iface}")
    return 0


def cmd_show(args):
    inv = load(args.inventory)
    ks = KeyStore(keys_path(args.inventory, args.keys))
    print(render_node(inv, ks, args.node), end="")
    ks.save()
    return 0


def cmd_rotate(args):
    inv = load(args.inventory)
    inv.get(args.node)
    ks = KeyStore(keys_path(args.inventory, args.keys))
    ks.rotate(args.node)
    ks.save()
    peers = [n.name for n in inv.nodes if n.name != args.node]
    print(f"new keys for {args.node}. Rebuild and redeploy {args.node} plus every node that peers with it "
          f"({len(peers)}): wgmesh build {args.inventory}")
    return 0


def cmd_graph(args):
    inv = load(args.inventory)
    links = plan(inv)
    print("graph LR")
    for n in inv.nodes:
        label = f"{n.name}<br/>{n.address.ip}"
        shape = f'(["{label}"])' if not n.public else f'["{label}"]'
        print(f"  {n.name.replace('-', '_')}{shape}")
    for l in links:
        a, b = l.a.replace("-", "_"), l.b.replace("-", "_")
        if l.kind == "direct":
            print(f"  {a} --- {b}")
        elif l.kind == "relayed":
            print(f"  {a} -. via {l.via} .- {b}")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="wgmesh", description=__doc__)
    ap.add_argument("--version", action="version", version=f"wgmesh {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("inventory")
        p.add_argument("--keys", help="key file (default: <inventory>.keys.json)")

    p = sub.add_parser("plan", help="show addresses, who peers with whom, and problems")
    common(p)
    p.set_defaults(fn=cmd_plan)

    p = sub.add_parser("build", help="write one wg-quick config per node")
    common(p)
    p.add_argument("-o", "--out", default="out")
    p.add_argument("-i", "--iface", default="wg0")
    p.add_argument("--force", action="store_true", help="write configs even with errors")
    p.set_defaults(fn=cmd_build)

    p = sub.add_parser("show", help="print one node's config")
    common(p)
    p.add_argument("node")
    p.set_defaults(fn=cmd_show)

    p = sub.add_parser("rotate", help="new keys for one node")
    common(p)
    p.add_argument("node")
    p.set_defaults(fn=cmd_rotate)

    p = sub.add_parser("graph", help="mermaid diagram of the tunnels")
    common(p)
    p.set_defaults(fn=cmd_graph)

    args = ap.parse_args(argv)
    try:
        return args.fn(args)
    except InventoryError as e:
        print(f"wgmesh: {args.inventory}: {e}", file=sys.stderr)
        return 2
    except KeyError as e:
        print(f"wgmesh: no node named {e}", file=sys.stderr)
        return 2
    except FileNotFoundError as e:
        print(f"wgmesh: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
