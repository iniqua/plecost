import asyncio

from typing import Dict, Union

from plecost.logger import Logger
from plecost.plugin import PlecostPluginsConfig, \
    PLUGIN_EXECUTION_ORDER

async def _get_results_as_dict_(module_name: str, coro):
    res = await coro

    if res:
        return {module_name: res}
    else:
        return {}

async def async_main(
        running_config: Dict[str, Union[str, int]],
        plugins_config: PlecostPluginsConfig
):
    # some sugar
    try:
        target = running_config["target"][0]

        if not target.endswith("/"):
            target = f"{target}/"

        if not target.startswith("http"):
            raise ValueError("Target must starts with 'http[s]://'")

        running_config["target"] = target

    except IndexError:
        raise ValueError("Target parameter is mandatory")

    #
    # Init plugins
    #
    for plugin_instance, _ in plugins_config.plugins:

        if hasattr(plugin_instance, "init"):
            Logger.debug(f"Initializing plugin: {plugin_instance.slug}")
            plugin_instance.init(running_config)

    tasks = set()
    pipeline_results = {}

    # Run the pipeline
    for step, m in PLUGIN_EXECUTION_ORDER.items():

        Logger.debug(f"{'#' * 10 } Running step: {step} {'#' * 10 }")

        # Run enabled plugins
        for plugin_instance, methods in plugins_config.plugins:

            # If plugin has implemented this method of pipeline
            if m in methods:
                Logger.debug(
                    f"Plugin '{plugin_instance.slug}' - Running method '{m}'"
                )

                try:
                    tasks.add(asyncio.create_task(
                        _get_results_as_dict_(
                            plugin_instance.slug,
                            getattr(plugin_instance, m)(**pipeline_results)
                        )
                    ))
                except Exception as e:
                    Logger.error(
                        f"Error on Plugin '{plugin_instance.slug}': {e} "
                    )
                    continue

        # Waiting for tasks
        ret = await asyncio.gather(*tasks)

        # Merge results
        step_result = {}

        for v in ret:
            if v and type(v) is dict:
                step_result.update(v)

        # Clear list
        tasks.clear()

        pipeline_results[f"{m}_results"] = step_result

