import ipaddress
import re

import pytest

from wgmesh.cli import check, main
from wgmesh.model import InventoryError, load, plan
from wgmesh.render import KeyStore, genkey, peers_for, pubkey, render_node

MESH = """
network: 10.9.0.0/24
nodes:
  a: {endpoint: 1.1.1.1}
  b: {routes: [192.168.1.0/24]}
  c: {routes: [192.168.2.0/24]}
  d: {}
"""

HUB = """
network: 10.8.0.0/24
topology: hub
hubs: [h1, h2]
nodes:
  h1: {endpoint: 1.1.1.1}
  h2: {endpoint: 2.2.2.2}
  s1: {routes: [172.20.1.0/24]}
  s2: {}
"""


def inv(text):
    return load(text, is_text=True)


def test_pubkey_matches_genkey():
    priv, pub = genkey()
    assert pubkey(priv) == pub
    assert len(priv) == 44 and priv.endswith("=")


def test_addresses_stable_and_skip_explicit():
    i = inv("network: 10.0.0.0/29\nnodes:\n  a: {}\n  b: {address: 10.0.0.1}\n  c: {}\n")
    assert [str(n.address.ip) for n in i.nodes] == ["10.0.0.2", "10.0.0.1", "10.0.0.3"]


def test_errors():
    with pytest.raises(InventoryError):
        inv("network: 10.0.0.0/30\nnodes: {a: {}, b: {}, c: {}}\n")         # full
    with pytest.raises(InventoryError):
        inv("network: 10.0.0.0/24\nnodes: {a: {address: 10.1.0.1}}\n")     # outside
    with pytest.raises(InventoryError):
        inv("network: 10.0.0.1/24\nnodes: {a: {}}\n")                       # host bits


def test_nat_pairs_relayed():
    links = {(l.a, l.b): l for l in plan(inv(MESH))}
    assert links[("b", "c")].kind == "relayed" and links[("b", "c")].via == "a"
    assert links[("a", "b")].kind == "direct"


def test_no_relay_is_an_error():
    i = inv("network: 10.0.0.0/24\nnodes: {a: {}, b: {}}\n")
    assert any(lv == "error" for lv, _ in check(i, plan(i)))


@pytest.mark.parametrize("text", [MESH, HUB])
def test_no_prefix_on_two_peers(text):
    # AllowedIPs is a longest-prefix-match table, so 10.8.0.0/24 on one peer
    # and 10.8.0.2/32 on another is fine (the /32 wins). The *same* prefix on
    # two peers is not: the second one silently takes it from the first.
    i = inv(text)
    links = plan(i)
    for n in i.nodes:
        owner = {}
        for peer, nets in peers_for(i, links, n.name).items():
            for net in ipaddress.collapse_addresses(nets):
                assert net not in owner, f"{n.name}: {net} on both {owner.get(net)} and {peer}"
                owner[net] = peer


@pytest.mark.parametrize("text", [MESH, HUB])
def test_everyone_can_reach_everyone(text):
    i = inv(text)
    links = plan(i)
    for me in i.nodes:
        covered = [net for nets in peers_for(i, links, me.name).values() for net in nets]
        for other in i.nodes:
            if other is me:
                continue
            for target in other.allowed():
                assert any(target.subnet_of(c) for c in covered), f"{me.name} can't reach {target}"


def test_keepalive_only_from_nat_side(tmp_path):
    i = inv(MESH)
    ks = KeyStore(str(tmp_path / "k.json"))
    a = render_node(i, ks, "a")
    b = render_node(i, ks, "b")
    assert "PersistentKeepalive" not in a
    assert "PersistentKeepalive = 25" in b
    assert "Endpoint = 1.1.1.1:51820" in b


def test_keys_survive_rebuild(tmp_path):
    p = str(tmp_path / "k.json")
    i = inv(MESH)
    ks = KeyStore(p)
    first = render_node(i, ks, "a")
    ks.save()
    again = render_node(i, KeyStore(p), "a")
    assert first == again


def test_forwarding_only_where_needed(tmp_path):
    i = inv(MESH)
    ks = KeyStore(str(tmp_path / "k.json"))
    assert "ip_forward" in render_node(i, ks, "a")       # relay
    assert "ip_forward" in render_node(i, ks, "b")       # has a LAN behind it
    assert "ip_forward" not in render_node(i, ks, "d")


def test_cli_build(tmp_path):
    f = tmp_path / "inv.yml"
    f.write_text(MESH)
    out = tmp_path / "out"
    assert main(["build", str(f), "-o", str(out)]) == 0
    confs = sorted(p.name for p in out.iterdir())
    assert confs == ["wg0-a.conf", "wg0-b.conf", "wg0-c.conf", "wg0-d.conf"]
    assert (out / "wg0-a.conf").stat().st_mode & 0o077 == 0
    assert (tmp_path / "inv.keys.json").stat().st_mode & 0o077 == 0
    # every PublicKey in a's config is someone else's, never a's own
    a = (out / "wg0-a.conf").read_text()
    own = pubkey(re.search(r"PrivateKey = (\S+)", a).group(1))
    assert own not in a
