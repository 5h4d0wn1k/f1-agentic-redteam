"""Plugin base class for campaign phases."""

from abc import ABC, abstractmethod


class PhasePlugin(ABC):
    """A single campaign phase.

    Subclasses implement dry_run() and run(). dry_run() returns the exact
    planned actions without doing anything; run() performs the phase and may
    emit findings through the run context.

    requires_approval marks a phase as security-relevant: the orchestrator
    stops for an interactive confirmation before executing it and ABORTS the
    whole campaign when running non-interactively.
    """

    name = ""
    title = ""
    phase = "recon"
    requires_approval = False
    description = ""

    def __init__(self, ctx, params=None):
        self.ctx = ctx
        self.params = dict(params or {})

    def needs_interaction(self):
        return bool(self.requires_approval)

    @abstractmethod
    def dry_run(self):
        """Return a list of planned action dicts {"action", "target", "detail"}.

        Must never execute anything.
        """

    @abstractmethod
    def run(self):
        """Execute the phase and return the executed action dicts."""