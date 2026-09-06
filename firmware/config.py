"""YAML-based configuration and campaign loading (stdlib-first).

Prefers PyYAML when installed; otherwise falls back to a strict subset
parser that covers the exact YAML subset this project ships. Campaign and
config files are deliberately written in that subset so the tool stays fully
offline-usable with zero dependencies.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path

from .errors import ConfigError
from .util import sha256_file

try:
    import yaml  # type: ignore
except ImportError:
    yaml = None

PHASE_NAMES = ("recon", "exploit", "post", "report")

_INT_RE = re.compile(r"^[-+]?\d+$")
_FLOAT_RE = re.compile(r"^[-+]?\d*\.\d+([eE][-+]?\d+)?$")


# ---------------------------------------------------------------------------
# Minimal YAML-subset parser (used only when PyYAML is unavailable)
# ---------------------------------------------------------------------------

def _split_top_level(text, sep=","):
    parts, buf, quote = [], [], None
    for ch in text:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
            buf.append(ch)
        elif ch == sep:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if quote:
        raise ConfigError("unterminated quote in scalar: %r" % text)
    parts.append("".join(buf))
    return parts


def _strip_comment(text):
    quote = None
    out = []
    for ch in text:
        if quote:
            out.append(ch)
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
            out.append(ch)
        elif ch == "#":
            break
        else:
            out.append(ch)
    return "".join(out).rstrip()


def _parse_scalar(raw):
    raw = raw.strip()
    if not raw:
        return None
    if raw in ("true", "True", "TRUE", "yes", "Yes"):
        return True
    if raw in ("false", "False", "FALSE", "no", "No"):
        return False
    if raw in ("null", "Null", "None", "~"):
        return None
    if raw.startswith('"'):
        if not raw.endswith('"'):
            raise ConfigError("unterminated double-quoted string: %r" % raw)
        return raw[1:-1]
    if raw.startswith("'"):
        if not raw.endswith("'"):
            raise ConfigError("unterminated single-quoted string: %r" % raw)
        return raw[1:-1]
    if _INT_RE.fullmatch(raw):
        return int(raw)
    if _FLOAT_RE.fullmatch(raw):
        return float(raw)
    return raw


def _parse_value(raw):
    raw = _strip_comment(raw).strip()
    if not raw:
        return None
    if raw.startswith("[") and raw.endswith("]"):
        inner = raw[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar(part) for part in _split_top_level(inner)]
    return _parse_scalar(raw)


class _SubsetParser(object):
    def __init__(self, text):
        lines = []
        for lineno, raw in enumerate(text.splitlines(), start=1):
            if not raw.strip():
                continue
            if raw.lstrip().startswith("#"):
                continue
            if "\t" in raw[:len(raw) - len(raw.lstrip())]:
                raise ConfigError("tabs are not allowed for indentation (line %d)" % lineno)
            lines.append((lineno, raw))
        self.lines = lines
        self.pos = 0

    def peek(self):
        if self.pos < len(self.lines):
            return self.lines[self.pos]
        return None

    @staticmethod
    def _indent(line):
        return len(line) - len(line.lstrip())

    def parse(self):
        node = self.parse_block(0)
        if isinstance(node, list):
            raise ConfigError("top-level document must be a mapping")
        return node

    def parse_block(self, base_indent):
        nxt = self.peek()
        if nxt is None or self._indent(nxt[1]) < base_indent:
            return {}
        if self._indent(nxt[1]) > base_indent:
            raise ConfigError("unexpected indentation at line %d" % nxt[0])
        if nxt[1].lstrip().startswith("- "):
            return self.parse_list(base_indent)
        return self.parse_map(base_indent)

    def parse_map(self, base_indent):
        result = {}
        while True:
            nxt = self.peek()
            if nxt is None or self._indent(nxt[1]) < base_indent:
                break
            if self._indent(nxt[1]) > base_indent:
                raise ConfigError("unexpected indentation at line %d" % nxt[0])
            text = nxt[1].strip()
            if text.startswith("-"):
                break
            if ":" not in text:
                raise ConfigError("expected 'key: value' at line %d" % nxt[0])
            key, _, rest = text.partition(":")
            key = key.strip()
            rest = rest.strip()
            self.pos += 1
            if rest:
                result[key] = _parse_value(rest)
                continue
            nxt2 = self.peek()
            if nxt2 is not None and self._indent(nxt2[1]) > base_indent:
                result[key] = self.parse_block(self._indent(nxt2[1]))
            else:
                result[key] = None
        return result

    def parse_list(self, base_indent):
        result = []
        while True:
            nxt = self.peek()
            if nxt is None or self._indent(nxt[1]) != base_indent:
                break
            text = nxt[1].lstrip()
            if not text.startswith("-"):
                break
            item = text[1:].strip()
            self.pos += 1
            if item and ":" in item:
                key, _, val = item.partition(":")
                node = {key.strip(): _parse_value(val)}
                while True:
                    nxt2 = self.peek()
                    if nxt2 is None:
                        break
                    if self._indent(nxt2[1]) <= base_indent:
                        break
                    cont = nxt2[1].lstrip()
                    if cont.startswith("-"):
                        raise ConfigError("nested lists unsupported by subset parser (line %d)"
                                          % nxt2[0])
                    if ":" not in cont:
                        raise ConfigError("expected 'key: value' at line %d" % nxt2[0])
                    k2, _, v2 = cont.partition(":")
                    node[k2.strip()] = _parse_value(v2)
                    self.pos += 1
                result.append(node)
            else:
                result.append(_parse_value(item) if item else None)
        return result


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def load_yaml_str(text):
    text = text.strip()
    if not text:
        return {}
    if yaml is not None:
        return yaml.safe_load(text) or {}
    if text.startswith("{"):
        # tolerate JSON when PyYAML is missing and the caller used JSON
        import json
        return json.loads(text)
    return _SubsetParser(text).parse()


def load_yaml(path):
    path = Path(path)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return load_yaml_str(fh.read())
    except OSError as exc:
        raise ConfigError("cannot read file %s: %s" % (path, exc))


# ---------------------------------------------------------------------------
# Typed views
# ---------------------------------------------------------------------------

@dataclass
class Opts(object):
    allowlist: list = field(default_factory=list)
    output_dir: str = "reports"
    audit_log: str = "logs/campaign.jsonl"
    log_dir: str = "logs"
    log_file: str = "orchestrator.log"
    log_level: str = "INFO"
    plugin_map: dict = field(default_factory=dict)
    external_tools: dict = field(default_factory=lambda: {"live_execution": False})


@dataclass
class PhaseSpec(object):
    phase: str
    plugin: str
    timebox_secs: int = None
    requires_approval: bool = False
    params: dict = field(default_factory=dict)


@dataclass
class Campaign(object):
    id: str
    name: str
    description: str
    targets: list
    phases: list
    max_phases: int = 30
    checksum: str = ""


def load_config(path):
    data = load_yaml(path)
    if not isinstance(data, dict):
        raise ConfigError("config file %s must contain a mapping" % path)
    opts = Opts()
    allow = data.get("allowlist", {})
    if isinstance(allow, dict):
        opts.allowlist = [str(c) for c in allow.get("cidrs", [])]
    elif isinstance(allow, list):
        opts.allowlist = [str(c) for c in allow]
    output = data.get("output", {})
    if isinstance(output, dict):
        opts.output_dir = str(output.get("dir", opts.output_dir))
        opts.audit_log = str(output.get("audit_log", opts.audit_log))
        opts.log_file = str(output.get("log_file", opts.log_file))
    log = data.get("logging", {})
    if isinstance(log, dict) and log.get("level"):
        opts.log_level = str(log["level"]).upper()
    pconf = data.get("plugins")
    if isinstance(pconf, dict):
        opts.plugin_map = pconf
    ext = data.get("external_tools", {})
    if isinstance(ext, dict):
        opts.external_tools = dict(ext)
    opts.external_tools.setdefault("live_execution", False)
    return opts


def load_campaign(path):
    path = Path(path)
    if not path.exists():
        raise ConfigError("campaign file not found: %s" % path)
    data = load_yaml(path)
    if not isinstance(data, dict):
        raise ConfigError("campaign file %s must contain a mapping" % path)
    missing = [k for k in ("id", "name", "targets", "phases") if not data.get(k)]
    if missing:
        raise ConfigError("campaign %s is missing required keys: %s"
                          % (path, ", ".join(missing)))
    targets = data["targets"]
    if not isinstance(targets, list) or not targets:
        raise ConfigError("campaign %s: 'targets' must be a non-empty list" % path)
    targets = [str(t) for t in targets]
    phases_raw = data["phases"]
    if not isinstance(phases_raw, list) or not phases_raw:
        raise ConfigError("campaign %s: 'phases' must be a non-empty list" % path)
    phases = []
    for i, entry in enumerate(phases_raw):
        if not isinstance(entry, dict):
            raise ConfigError("campaign %s: phase %d must be a mapping" % (path, i + 1))
        phase = str(entry.get("phase", ""))
        plugin = str(entry.get("plugin", ""))
        if phase not in PHASE_NAMES:
            raise ConfigError("campaign %s: phase %d has invalid phase %r "
                              "(expected one of %s)" % (path, i + 1, phase, PHASE_NAMES))
        if not plugin:
            raise ConfigError("campaign %s: phase %d is missing 'plugin'" % (path, i + 1))
        timebox = entry.get("timebox_secs")
        if timebox is not None and (not isinstance(timebox, int) or timebox < 0):
            raise ConfigError("campaign %s: phase %d timebox_secs must be a "
                              "non-negative int" % (path, i + 1))
        params = entry.get("params")
        if not isinstance(params, dict):
            params = {}
        phases.append(PhaseSpec(
            phase=phase,
            plugin=plugin,
            timebox_secs=timebox,
            requires_approval=bool(entry.get("requires_approval", False)),
            params=dict(params),
        ))
    max_phases = data.get("max_phases", 30)
    if not isinstance(max_phases, int) or max_phases < 1:
        raise ConfigError("campaign %s: max_phases must be a positive int" % path)
    return Campaign(
        id=str(data["id"]),
        name=str(data["name"]),
        description=str(data.get("description", "")),
        targets=targets,
        phases=phases,
        max_phases=max_phases,
        checksum=sha256_file(path),
    )