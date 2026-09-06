"""Plugin registry: name -> PhasePlugin subclass."""

_REGISTRY = {}


def register(cls):
    if not getattr(cls, "name", ""):
        raise ValueError("plugin class %r must define a name" % cls.__name__)
    _REGISTRY[cls.name] = cls
    return cls


def get_plugin(name):
    return _REGISTRY.get(name)


def all_plugins():
    return sorted(_REGISTRY.values(), key=lambda c: c.name)