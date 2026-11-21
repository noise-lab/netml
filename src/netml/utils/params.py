"""Parameter helpers shared by the NDM detectors."""
import warnings

HINTS = {"AE": " (seed PyTorch with torch.manual_seed() instead)"}


def check_ignored_random_state(kwargs, name):
    """Accept a legacy ``random_state`` keyword that this detector ignores.

    Warn that it has no effect, and reject any other unexpected keyword, so
    that a misspelled parameter is not silently swallowed by ``**kwargs``.
    """
    unexpected = set(kwargs) - {'random_state'}
    if unexpected:
        raise TypeError(f"{name}() got unexpected keyword argument(s): {', '.join(sorted(unexpected))}")
    if 'random_state' in kwargs:
        warnings.warn(f"'random_state' has no effect on {name}{HINTS.get(name, '')}; it is ignored.",
                      UserWarning, stacklevel=3)
