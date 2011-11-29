django-werkzeug-debugger-runserver
==================================

This app extracts the runserver_plus_ management command from 
`django-extensions`_ and makes it available as a replacement for Django's
default ``runserver`` management command.


Installation
------------

Install from PyPI::

    pip install django-werkzeug-debugger-runserver


Configuration
-------------

Edit your ``settings.py`` and include ``werkzeug_debugger_runserver`` in your
``INSTALLED_APPS``::

    INSTALLED_APPS = (
        ...,
        'werkzeug_debugger_runserver',
    )


.. _django-extensions: https://github.com/django-extensions/django-extensions/
.. _runserver_plus: http://packages.python.org/django-extensions/runserver_plus.html
