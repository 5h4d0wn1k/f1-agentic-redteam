"""Target allowlist validation against lab CIDR ranges.

Hard safety rail: every campaign target must be an IP or CIDR fully contained
inside one of the allowlisted lab networks held in config/orchestrator.yaml.
Hostnames are deliberately rejected - only numeric IP/CIDR targets are valid,
which keeps the allowlist check honest.
"""

import ipaddress

from .errors import ConfigError

# RFC 5737 documentation ranges. These are placeholders and can never be a
# real lab network; external tooling refuses to execute against them.
DOC_RANGES = ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")


class Allowlist(object):
    def __init__(self, cidrs):
        if not cidrs:
            raise ConfigError("allowlist is empty: configure lab CIDRs in "
                              "config/orchestrator.yaml before --execute")
        self._nets = []
        for c in cidrs:
            try:
                self._nets.append(ipaddress.ip_network(str(c).strip(), strict=False))
            except ValueError as exc:
                raise ConfigError("invalid allowlist CIDR %r: %s" % (c, exc))

    def validate(self, target):
        target = str(target).strip()
        if not target:
            return False, "empty target"
        try:
            addr = ipaddress.ip_address(target)
        except ValueError:
            try:
                net = ipaddress.ip_network(target, strict=False)
            except ValueError:
                return False, ("target %r is not a valid IP or CIDR "
                               "(hostnames are not allowed)" % target)
            for base in self._nets:
                if base.supernet_of(net):
                    return True, "ok"
            return False, ("target CIDR %s is not contained in the allowlist "
                           "(%s)" % (target, ", ".join(str(n) for n in self._nets)))
        for base in self._nets:
            if addr in base:
                return True, "ok"
        return False, ("target %s does not fall inside the allowlist %s"
                       % (target, ", ".join(str(n) for n in self._nets)))

    def validate_all(self, targets):
        bad = []
        for t in targets:
            ok, msg = self.validate(t)
            if not ok:
                bad.append((t, msg))
        return bad


def is_documentation_target(target):
    """True when a target lies inside an RFC 5737 documentation range."""
    try:
        ip = ipaddress.ip_address(str(target))
    except ValueError:
        try:
            net = ipaddress.ip_network(str(target), strict=False)
        except ValueError:
            return False
        return any(net.subnet_of(ipaddress.ip_network(d)) for d in DOC_RANGES)
    return any(ip in ipaddress.ip_network(d) for d in DOC_RANGES)