Plecost development guide
=========================

Pre-installed python libraries
------------------------------

- tqdm
- aiohttp
- whoosh
- orjson
- termcolor

Plugin steps and method
-----------------------

- Step 1 -> on_start
- Step 2 -> on_finding_wordpress
- Step 3 -> on_plugin_discovery
- Step 4 -> on_plugin_found
- Step 5 -> on_before_stop

Method functions signatures
---------------------------

on_start
++++++++

.. code-block:: python

    async def on_start(self):
        ...

on_finding_wordpress
++++++++++++++++++++

.. code-block:: python

    async def on_finding_wordpress(self, on_start_results: dict):
        ...

on_plugin_discovery
++++++++++++++++++++

.. code-block:: python

    async def on_plugin_discovery(
        self,
        on_start_results: dict,
        on_finding_wordpress_results: dict
    ):
        ...

on_plugin_discovery
++++++++++++++++++++

.. code-block:: python

    async def on_plugin_found(
        self,
        on_start_results: dict,
        on_finding_wordpress_results: dict,
        on_plugin_discovery: dict
    ):
        ...

on_before_stop
++++++++++++++++++++

.. code-block:: python

    async def on_before_stop(
        self,
        on_start_results: dict,
        on_finding_wordpress_results: dict,
        on_plugin_discovery: dict,
        on_plugin_found: dict.
    ):
        ...
