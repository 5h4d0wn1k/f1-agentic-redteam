"""Exception hierarchy and process exit codes for the F1 orchestrator."""

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_ABORTED = 3
EXIT_SIGINT = 130


class RTError(Exception):
    """Base class for F1 runtime errors."""

    exit_code = EXIT_ERROR


class ConfigError(RTError):
    exit_code = EXIT_USAGE


class ValidationError(RTError):
    exit_code = EXIT_USAGE


class TargetNotAllowed(ValidationError):
    pass


class UnknownPlugin(ValidationError):
    pass


class PluginError(RTError):
    exit_code = EXIT_ERROR


class PluginUnavailable(PluginError):
    pass


class AbortError(RTError):
    exit_code = EXIT_ABORTED


class ApprovalGateAbort(AbortError):
    pass


class MaxPhasesAbort(AbortError):
    pass


class TimeboxAbort(AbortError):
    pass