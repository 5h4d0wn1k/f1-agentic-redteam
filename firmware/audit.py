"""JSONL audit log recording every orchestrator action.

Every entry carries a timestamp, campaign id, and the sha256 checksum of the
campaign file at load time, so an offline reader can verify a campaign never
drifted from an approved definition.
"""

import json
from pathlib import Path

from .util import now_iso


class AuditLog(object):
    def __init__(self, path):
        self.path = Path(path)

    def _append(self, entry):
        entry.setdefault("ts", now_iso())
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")

    def start(self, *, mode, campaign_id, campaign_sha256, targets):
        self._append({"event": "start", "mode": mode, "campaign_id": campaign_id,
                      "campaign_sha256": campaign_sha256, "targets": list(targets)})

    def action(self, *, mode, campaign_id, campaign_sha256, phase, plugin,
               target, action, detail="", executed=False):
        self._append({"event": "action", "mode": mode, "campaign_id": campaign_id,
                      "campaign_sha256": campaign_sha256, "phase": phase,
                      "plugin": plugin, "target": target, "action": action,
                      "detail": detail, "executed": executed})

    def abort(self, *, reason, campaign_id, campaign_sha256, phase="",
              plugin="", detail=""):
        self._append({"event": "abort", "reason": reason, "campaign_id": campaign_id,
                      "campaign_sha256": campaign_sha256, "phase": phase,
                      "plugin": plugin, "detail": detail})

    def end(self, *, status, campaign_id, campaign_sha256, detail=""):
        self._append({"event": "end", "status": status, "campaign_id": campaign_id,
                      "campaign_sha256": campaign_sha256, "detail": detail})

    def read_entries(self):
        if not self.path.exists():
            return []
        out = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out