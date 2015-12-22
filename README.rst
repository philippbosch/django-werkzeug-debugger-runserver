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
``INSTALLED_APPS`` before ``django.contrib.staticfiles``::

    INSTALLED_APPS = (
        # ...
        'werkzeug_debugger_runserver',
        'django.contrib.staticfiles',
        # ...
    )


Usage
-----

Start the development server using ``python manage.py runserver`` as usual. If
you run into an error the debugger-enabled error view will be shown in the
browser. If you want to force the debugger view to appear you can do it using
something like ``raise Exception`` in your code.



.. _django-extensions: https://github.com/django-extensions/django-extensions/
.. _runserver_plus: http://packages.python.org/django-extensions/runserver_plus.html
