"""Workspace storage for PENTRIX ARSENAL.

Layout per target:
    workspaces/<safe>/scans/<module>/<ts>.json   individual module runs
    workspaces/<safe>/findings.json              aggregate findings
    workspaces/<safe>/meta.json                  target metadata
    workspaces/<safe>/pipeline_state.json        resume state (pipeline)
"""

import glob
import json
import os
import re
from datetime import datetime, timezone


class Workspace:
    def __init__(self, root="~/.arsenal/workspaces"):
        self.root = os.path.expanduser(root)
        os.makedirs(self.root, exist_ok=True)

    @staticmethod
    def safe_name(target):
        """Map an arbitrary target string to a safe directory name."""
        name = re.sub(r"[^A-Za-z0-9_.-]", "_", str(target).strip())
        return name.lower() or "unknown"

    def path(self, target):
        """Return (creating) the workspace directory for a target."""
        p = os.path.join(self.root, self.safe_name(target))
        os.makedirs(p, exist_ok=True)
        return p

    def _findings_file(self, target):
        return os.path.join(self.path(target), "findings.json")

    def _meta_file(self, target):
        return os.path.join(self.path(target), "meta.json")

    @staticmethod
    def _read_json(path, default):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return default

    @staticmethod
    def _write_json(path, payload):
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        os.replace(tmp, path)

    def save_scan(self, target, module, findings):
        """Persist one module run; returns the filepath written."""
        d = os.path.join(self.path(target), "scans", self.safe_name(module))
        os.makedirs(d, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        fp = os.path.join(d, ts + ".json")
        self._write_json(fp, {
            "target": target,
            "module": module,
            "ts": ts,
            "findings": list(findings),
        })
        self._touch_meta(target)
        return fp

    def latest_scan(self, target, module):
        """Return the filepath of the newest scan for module, or None."""
        d = os.path.join(self.path(target), "scans", self.safe_name(module))
        files = sorted(glob.glob(os.path.join(d, "*.json")))
        return files[-1] if files else None

    def all_findings(self, target):
        """Return the aggregate findings list for a target."""
        data = self._read_json(self._findings_file(target), [])
        return data if isinstance(data, list) else []

    def write_findings(self, target, findings):
        """Overwrite the aggregate findings file (used after re-triage)."""
        self._write_json(self._findings_file(target), list(findings))
        self._touch_meta(target)

    def append_findings(self, target, findings):
        """Merge findings into the aggregate, deduped by module+title+target.

        Returns the number of findings actually added.
        """
        current = self.all_findings(target)
        seen = set()
        for item in current:
            if isinstance(item, dict):
                seen.add((item.get("module"), item.get("title"), item.get("target")))
        added = 0
        for item in findings:
            if not isinstance(item, dict):
                continue
            key = (item.get("module"), item.get("title"), item.get("target"))
            if key in seen:
                continue
            seen.add(key)
            current.append(item)
            added += 1
        self._write_json(self._findings_file(target), current)
        self._touch_meta(target)
        return added

    def save_blob(self, target, relpath, data):
        """Save an opaque blob (bytes or str) under the target directory.

        Used for fetched JS, wordlists, screenshots. Returns the filepath.
        """
        fp = os.path.join(self.path(target), relpath)
        os.makedirs(os.path.dirname(fp), exist_ok=True)
        mode = "wb" if isinstance(data, (bytes, bytearray)) else "w"
        with open(fp, mode) as fh:
            fh.write(data)
        return fp

    def search(self, query):
        """Return [(target, finding), ...] where query matches the finding."""
        q = str(query).lower()
        hits = []
        for target in self.list_targets():
            for item in self.all_findings(target):
                try:
                    blob = json.dumps(item).lower()
                except (TypeError, ValueError):
                    continue
                if q in blob:
                    hits.append((target, item))
        return hits

    def list_targets(self):
        """Return sorted workspace directory names (one per target)."""
        try:
            entries = os.listdir(self.root)
        except OSError:
            return []
        return sorted(e for e in entries
                      if os.path.isdir(os.path.join(self.root, e)))

    def _touch_meta(self, target):
        mf = self._meta_file(target)
        meta = self._read_json(mf, {})
        if not isinstance(meta, dict):
            meta = {}
        now = datetime.now(timezone.utc).isoformat()
        meta.setdefault("target", target)
        meta.setdefault("created", now)
        meta["updated"] = now
        self._write_json(mf, meta)
