Quick start guide
=================

The use of package is very simple. This document is a brief explanation.

Installation
------------

Install the package is so easy. Simple type this:

.. code-block:: bash

    > sudo pip install openvas2document

.. note::

    Remember that you need **Python 3**!!


Generate Excel
--------------

To generate an Excel File you need to export the OpenVAS results as a XML format. If you can't a report by hand, you can find one in :file:`example` folder.

Then, you need to use :samp:`openvas_to_document` tool:

.. code-block:: bash

    > openvas_to_document -i my_openvas_report.xml -o generated_excel.xslx

For further information go to the :ref:`Openvas to report manual <openvas_to_document_man>`.

Filter results
--------------

If you want to filter the XML OpenVAS file, deleting some targets for example, and generate a new XML document without this information, you can user :samp:`openvas_cutter`

First we create a file with the targets that we want to remove.

.. code-block::  bash

    > echo 10.0.1.1 > remove_targets.txt

Now launch the script:

.. code-block:: bash

    > openvas_cutter -i my_openvas_report.xml -o my_openvas_report_filtered.xml --exclude-hosts remove_targets.txt

For further information go to the :ref:`Openvas cutter manual <openvas_cutter_man>`.


As a library
------------

You also can use the library in your won code, importing as a usual lib. After install de library, using bellow instructions, you only must do:

.. code-block:: python

    from openvas_to_report.api import Config, convert

    c = Config(input_files=["input_file.xml"], output_file="results.xslx")
    convert(c)

For further information go to the :ref:`Openvas as library manual <openvas_library_man>`.