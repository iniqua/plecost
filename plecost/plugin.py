import os
import asyncio

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, List, Set, Optional, Tuple, Any

from pluginbase import PluginBase

from plecost.exceptions import PlecostPluginError
from plecost.utils import get_installed_dependencies

HERE = os.path.abspath(os.path.dirname(__file__))

PLUGIN_EXECUTION_ORDER = {
    "001": "on_start",
    "002": "on_finding_wordpress",
    "003": "on_plugin_discovery",
    "004": "on_plugin_found",
    "005": "on_before_stop",
}
PLUGIN_CORO_METHODS = tuple(PLUGIN_EXECUTION_ORDER.values())

PLUGIN_METHODS = (
    "on_update",
    "cli_run",
    "cli_update",
)


@dataclass
class PlecostPluginsConfig:
    slug_names: Set = field(default_factory=set)
    cli_run: List[Callable] = field(default_factory=list)
    cli_update: List[Callable] = field(default_factory=list)
    plugins: List[Tuple[Any, Tuple[str]]] = field(default_factory=list)

    # on_start: List[Callable] = field(default_factory=list)
    # on_finding_wordpress: List[Callable] = field(default_factory=list)
    # on_plugin_foundstart: List[Callable] = field(default_factory=list)
    # on_information_found: List[Callable] = field(default_factory=list)
    # on_update: List[Callable] = field(default_factory=list)

def find_plugins(
        module,
        found_functions: PlecostPluginsConfig,
        disable_plugins: Optional[List[str]] = None,
        only_enable_plugins: Optional[List[str]] = None,
):

    for class_name, klass in vars(module).items():
        if class_name.startswith("_"):
            continue

        if not class_name.startswith("Plecost"):
            continue

        props = tuple(x for x in vars(klass).keys() if not x.startswith("_"))

        #
        # Check if have plugin requisites
        #

        # Mandatory properties
        if not all(x in props for x in ("slug", "name", "description")):
            raise PlecostPluginError(
                f"Plugin Class: '{class_name}': "
                "Plugins must have mandatory properties: "
                "'name' and 'description'"
            )

        # Ensure plugin name is unique
        if klass.slug in found_functions.slug_names:
            raise PlecostPluginError(
                f"Plugin name '{klass.name}' already exits"
            )
        else:
            found_functions.slug_names.add(klass.slug)

        # Enable / Disable selected plugins
        if only_enable_plugins and klass.slug not in disable_plugins:
            continue

        elif disable_plugins and klass.slug in disable_plugins:
            continue

        # Ensure plugin has any method
        if not any(x in props for x in PLUGIN_CORO_METHODS):
            raise PlecostPluginError(
                f"Plugin Class: '{class_name}': "
                "a Plecost plugin must contains, at least, one of "
                f"these methods: \"{','.join(PLUGIN_CORO_METHODS)}\""
            )

        # Ensure methods are coroutines
        klass_instance = klass()
        klass_functions = []

        for m in PLUGIN_CORO_METHODS:

            if coro_fn := getattr(klass_instance, m, None):

                if not asyncio.iscoroutinefunction(coro_fn):
                    raise PlecostPluginError(
                        f"Plugin Class: '{class_name}': "
                         f"{m} must be a coroutine. Try defining method as "
                        "'async def...' instead "
                        "of 'def ...': "
                    )

                klass_functions.append(m)

        for m in PLUGIN_METHODS:

            if fn := getattr(klass_instance, m, None):

                if asyncio.iscoroutinefunction(fn):
                    raise PlecostPluginError(
                        f"Plugin Class: '{class_name}': "
                        f"'cli_parser' must be a function, not a coroutine. "
                        "Try defining method as def...' instead "
                        "of async 'def ...': "
                    )

                # getattr(found_functions, m)[klass.slug_name] = fn
                if m.startswith("cli"):
                    getattr(found_functions, m).append(fn)
                else:
                    klass_functions.append(m)

        found_functions.plugins.append(
            (klass_instance, tuple(klass_functions))
        )

async def async_main(fn: PlecostPluginsConfig):

    tasks = set()

    for m in PLUGIN_CORO_METHODS:
        for coro in getattr(fn, m):
            tasks.add(asyncio.create_task(coro()))

        await asyncio.gather(*tasks)
        tasks.clear()


def discover_plugins(
        disable_plugins: Optional[List[str]] = None,
        only_enable_plugins: Optional[List[str]] = None,
        base_paths: Optional[List[str]] = None,
) -> PlecostPluginsConfig:

    internal_paths = [
        os.path.join(HERE, "core_plugins"),
        os.path.join(os.path.expanduser("~"), ".plecost", "core_plugins")
    ]

    if not base_paths:
        base_paths = internal_paths
    else:
        base_paths.extend(internal_paths)

    functions_bucket = PlecostPluginsConfig()


    plugin_base = PluginBase(package='plecost.plugins')

    sources = []
    requirements_files = defaultdict(list)

    for path in base_paths:

        if not os.path.exists(path):
            continue

        for plugin_path in os.listdir(path):

            plugin_dir = os.path.join(path, plugin_path)

            sources.append(plugin_dir)

            if "requirements.txt" in os.listdir(plugin_dir):
                with open(os.path.join(plugin_dir, "requirements.txt" ), "r") as f:
                    for dep in set(f.read().splitlines()):
                        requirements_files[dep].append(plugin_path)

    # -------------------------------------------------------------------------
    # Install missing dependencies for plugins
    # -------------------------------------------------------------------------
    if need_to_install := set(requirements_files.keys()) - get_installed_dependencies():
        print("[!] Missing dependencies:")

        for need in need_to_install:
            print(f"    - Dependency '{need}' is needed by: {','.join(requirements_files[need])}")

        print("\nYou can install these dependencies executing: \n")
        print(f"    python3 -m pip install {' '.join(need_to_install)}")

        exit(1)

    # -------------------------------------------------------------------------
    # Load plugins
    # -------------------------------------------------------------------------
    plugin_source = plugin_base.make_plugin_source(
        searchpath=sources,
        persist=True
    )

    for plugin in plugin_source.list_plugins():
        find_plugins(
            plugin_source.load_plugin(plugin),
            functions_bucket,
            disable_plugins,
            only_enable_plugins
        )

    return functions_bucket
