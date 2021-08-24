from typing import Set
from pkgutil import iter_modules

def get_installed_dependencies() -> Set[str]:
    return {p.name for p in iter_modules() if not p.name.startswith("_")}
