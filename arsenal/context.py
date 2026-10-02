"""Shared context object passed to every module and pipeline stage.

The Ctx carries runtime state (config, logger, workspace, scope) plus the
safety flags that gate active behaviour.  Modules must never invent their
own safety policy; they read it from here.
"""


class Ctx:
    """Runtime context.

    Attributes:
        config: merged configuration dict.
        log: logging.Logger (may be None in minimal test usage).
        workspace: arsenal.workspace.Workspace instance.
        scope: object exposing .contains(host) -> bool, or None when no
            scope file was provided.
        safe_mode: when True, intrusive actions require explicit opt-in.
        allow_intrusive: True only when the user passed --intrusive (and
            the run is not passive).
        console: rich Console or None. Only the CLI sets this, and rich
            is imported only in arsenal/cli.py.
        passive: True in passive-only mode. Guarantees zero active
            packets to the target.
        resume: True when resuming a previous pipeline run from saved state.
    """

    def __init__(self, config=None, log=None, workspace=None, scope=None,
                 safe_mode=True, allow_intrusive=False, console=None,
                 passive=False, resume=False):
        self.config = config if config is not None else {}
        self.log = log
        self.workspace = workspace
        self.scope = scope
        self.safe_mode = safe_mode
        self.allow_intrusive = allow_intrusive
        self.console = console
        self.passive = passive
        self.resume = resume

    def save_config(self):
        """Persist the current config dict via arsenal.config.save()."""
        try:
            from arsenal import config as config_mod
            config_mod.save(self.config)
        except Exception:
            pass


def make_ctx(config=None, log=None, workspace=None, scope=None,
             safe_mode=True, allow_intrusive=False, console=None,
             passive=False, resume=False):
    """Build a Ctx with the given pieces."""
    return Ctx(config=config, log=log, workspace=workspace, scope=scope,
               safe_mode=safe_mode, allow_intrusive=allow_intrusive,
               console=console, passive=passive, resume=resume)
