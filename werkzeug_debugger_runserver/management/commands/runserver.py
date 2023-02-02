import os
import re
import six
import socket
import sys
import time
import argparse

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError


try:
    if 'django.contrib.staticfiles' in settings.INSTALLED_APPS:
        from django.contrib.staticfiles.handlers import StaticFilesHandler
        USE_STATICFILES = True
    elif 'staticfiles' in settings.INSTALLED_APPS:
        from staticfiles.handlers import StaticFilesHandler  # noqa
        USE_STATICFILES = True
    else:
        USE_STATICFILES = False
except ImportError:
    USE_STATICFILES = False


naiveip_re = re.compile(r"""^(?:
(?P<addr>
    (?P<ipv4>\d{1,3}(?:\.\d{1,3}){3}) |         # IPv4 address
    (?P<ipv6>\[[a-fA-F0-9:]+\]) |               # IPv6 address
    (?P<fqdn>[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*) # FQDN
):)?(?P<port>\d+)$""", re.X)
DEFAULT_PORT = "8000"


import logging
logger = logging.getLogger(__name__)


def setup_logger(logger, stream, filename=None, fmt=None):
    """Sets up a logger (if no handlers exist) for console output,
    and file 'tee' output if desired."""
    if len(logger.handlers) < 1:
        console = logging.StreamHandler(stream)
        console.setLevel(logging.DEBUG)
        console.setFormatter(logging.Formatter(fmt))
        logger.addHandler(console)
        logger.setLevel(logging.DEBUG)

        if filename:
            outfile = logging.FileHandler(filename)
            outfile.setLevel(logging.INFO)
            outfile.setFormatter(logging.Formatter("%(asctime)s " + (fmt if fmt else '%(message)s')))
            logger.addHandler(outfile)


class RedirectHandler(logging.Handler):
    """Redirect logging sent to one logger (name) to another."""
    def __init__(self, name, level=logging.DEBUG):
        # Contemplate feasibility of copying a destination (allow original handler) and redirecting.
        logging.Handler.__init__(self, level)
        self.name = name
        self.logger = logging.getLogger(name)

    def emit(self, record):
        self.logger.handle(record)


def null_technical_500_response(request, exc_type, exc_value, tb):
    six.reraise(exc_type, exc_value, tb)


class Command(BaseCommand):
    def add_arguments(self, parser):

        parser.add_argument('bind_address', nargs=argparse.REMAINDER,
                            help='optional port number, or ipaddr:port')

        parser.add_argument('--ipv6', '-6', action='store_true', dest='use_ipv6',
                            default=False, help='Tells Django to use a IPv6 address.'),
        parser.add_argument('--noreload', action='store_false', dest='use_reloader',
                            default=True, help='Tells Django to NOT use the auto-reloader.')
        parser.add_argument('--browser', action='store_true', dest='open_browser',
                            help='Tells Django to open a browser.')
        parser.add_argument('--adminmedia', dest='admin_media_path', default='',
                            help='Specifies the directory from which to serve admin media.')
        parser.add_argument('--threaded', action='store_true', dest='threaded',
                            help='Run in multithreaded mode.')
        parser.add_argument('--output', dest='output_file', default=None,
                            help='Specifies an output file to send a copy of all messages (not flushed immediately).')
        parser.add_argument('--print-sql', action='store_true', default=False,
                            help="Print SQL queries as they're executed")
        parser.add_argument('--cert', dest='cert_path', action="store",
                            help='To use SSL, specify certificate path.')

        if USE_STATICFILES:
            parser.add_argument('--nostatic', action="store_false", dest='use_static_handler', default=True,
                                help='Tells Django to NOT automatically serve static files at STATIC_URL.')
            parser.add_argument('--insecure', action="store_true", dest='insecure_serving', default=False,
                                help='Allows serving static files even if DEBUG is False.')

    help = "Starts a lightweight Web server for development."

    # Validation is called explicitly each time the server is reloaded.
    requires_model_validation = False

    def handle(self, *args, **options):
        import django

        addrport = options['bind_address'][0] if options['bind_address'] else None
        setup_logger(logger, self.stderr, filename=options.get('output_file', None))  # , fmt="[%(name)s] %(message)s")
        logredirect = RedirectHandler(__name__)

        # Redirect werkzeug log items
        werklogger = logging.getLogger('werkzeug')
        werklogger.setLevel(logging.INFO)
        werklogger.addHandler(logredirect)
        werklogger.propagate = False

        if options.get("print_sql", False):
            from django.db.backends import utils
            try:
                import sqlparse
            except ImportError:
                sqlparse = None  # noqa

            class PrintQueryWrapper(utils.CursorDebugWrapper):
                def execute(self, sql, params=()):
                    starttime = time.time()
                    try:
                        return self.cursor.execute(sql, params)
                    finally:
                        raw_sql = self.db.ops.last_executed_query(self.cursor, sql, params)
                        execution_time = time.time() - starttime
                        therest = ' -- [Execution time: %.6fs] [Database: %s]' % (execution_time, self.db.alias)
                        if sqlparse:
                            logger.info(sqlparse.format(raw_sql, reindent=True) + therest)
                        else:
                            logger.info(raw_sql + therest)

            utils.CursorDebugWrapper = PrintQueryWrapper

        try:
            from django.core.servers.basehttp import AdminMediaHandler
            USE_ADMINMEDIAHANDLER = True
        except ImportError:
            USE_ADMINMEDIAHANDLER = False

        try:
            from django.core.servers.basehttp import get_internal_wsgi_application as WSGIHandler
        except ImportError:
            from django.core.handlers.wsgi import WSGIHandler  # noqa

        try:
            from werkzeug import run_simple
            from werkzeug.debug import DebuggedApplication

            # Set colored output
            if settings.DEBUG:
                try:
                    set_werkzeug_log_color()
                except:     # We are dealing with some internals, anything could go wrong
                    print("Wrapping internal werkzeug logger for color highlighting has failed!")
                    pass

        except ImportError:
            raise CommandError("Werkzeug is required to use runserver_plus.  Please visit http://werkzeug.pocoo.org/ or install via pip. (pip install Werkzeug)")

        # usurp django's handler
        from django.views import debug
        debug.technical_500_response = null_technical_500_response

        self.use_ipv6 = options.get('use_ipv6')
        if self.use_ipv6 and not socket.has_ipv6:
            raise CommandError('Your Python does not support IPv6.')
        self._raw_ipv6 = False
        if not addrport:
            try:
                addrport = settings.RUNSERVERPLUS_SERVER_ADDRESS_PORT
            except AttributeError:
                pass
        if not addrport:
            self.addr = ''
            self.port = DEFAULT_PORT
        else:
            m = re.match(naiveip_re, addrport)
            if m is None:
                raise CommandError('"%s" is not a valid port number '
                                   'or address:port pair.' % addrport)
            self.addr, _ipv4, _ipv6, _fqdn, self.port = m.groups()
            if not self.port.isdigit():
                raise CommandError("%r is not a valid port number." %
                                   self.port)
            if self.addr:
                if _ipv6:
                    self.addr = self.addr[1:-1]
                    self.use_ipv6 = True
                    self._raw_ipv6 = True
                elif self.use_ipv6 and not _fqdn:
                    raise CommandError('"%s" is not a valid IPv6 address.'
                                       % self.addr)
        if not self.addr:
            self.addr = '::1' if self.use_ipv6 else '127.0.0.1'

        threaded = options.get('threaded', False)
        use_reloader = options.get('use_reloader', True)
        open_browser = options.get('open_browser', False)
        cert_path = options.get("cert_path")
        quit_command = (sys.platform == 'win32') and 'CTRL-BREAK' or 'CONTROL-C'
        bind_url = "http://%s:%s/" % (
            self.addr if not self._raw_ipv6 else '[%s]' % self.addr, self.port)

        def inner_run():
            print("Validating models...")
            try:
                self.check(display_num_errors=True)
            except AttributeError:
                self.validate(display_num_errors=True)
            print("\nDjango version %s, using settings %r" % (django.get_version(), settings.SETTINGS_MODULE))
            print("Development server is running at %s" % (bind_url,))
            print("Using the Werkzeug debugger (http://werkzeug.pocoo.org/)")
            print("Quit the server with %s." % quit_command)
            path = options.get('admin_media_path', '')
            if not path:
                admin_media_path = os.path.join(django.__path__[0], 'contrib/admin/static/admin')
                if os.path.isdir(admin_media_path):
                    path = admin_media_path
                else:
                    path = os.path.join(django.__path__[0], 'contrib/admin/media')
            handler = WSGIHandler()
            if USE_ADMINMEDIAHANDLER:
                handler = AdminMediaHandler(handler, path)
            if USE_STATICFILES:
                use_static_handler = options.get('use_static_handler', True)
                insecure_serving = options.get('insecure_serving', False)
                if use_static_handler and (settings.DEBUG or insecure_serving):
                    handler = StaticFilesHandler(handler)
            if open_browser:
                import webbrowser
                webbrowser.open(bind_url)
            if cert_path:
                """
                OpenSSL is needed for SSL support.

                This will make flakes8 throw warning since OpenSSL is not used
                directly, alas, this is the only way to show meaningful error
                messages. See:
                http://lucumr.pocoo.org/2011/9/21/python-import-blackbox/
                for more information on python imports.
                """
                try:
                    import OpenSSL  # NOQA
                except ImportError:
                    raise CommandError("Python OpenSSL Library is "
                                       "required to use runserver_plus with ssl support. "
                                       "Install via pip (pip install pyOpenSSL).")

                dir_path, cert_file = os.path.split(cert_path)
                if not dir_path:
                    dir_path = os.getcwd()
                root, ext = os.path.splitext(cert_file)
                certfile = os.path.join(dir_path, root + ".crt")
                keyfile = os.path.join(dir_path, root + ".key")
                try:
                    from werkzeug.serving import make_ssl_devcert
                    if os.path.exists(certfile) and \
                            os.path.exists(keyfile):
                                ssl_context = (certfile, keyfile)
                    else:  # Create cert, key files ourselves.
                        ssl_context = make_ssl_devcert(
                            os.path.join(dir_path, root), host='localhost')
                except ImportError:
                    print("Werkzeug version is less than 0.9, trying adhoc certificate.")
                    ssl_context = "adhoc"

            else:
                ssl_context = None
            run_simple(
                self.addr,
                int(self.port),
                DebuggedApplication(handler, True),
                use_reloader=use_reloader,
                use_debugger=True,
                threaded=threaded,
                ssl_context=ssl_context
            )
        inner_run()


def set_werkzeug_log_color():
    """Try to set color to the werkzeug log.
    """
    from django.core.management.color import color_style
    from werkzeug.serving import WSGIRequestHandler
    from werkzeug._internal import _log

    _style = color_style()
    _orig_log = WSGIRequestHandler.log

    def werk_log(self, type, message, *args):
        try:
            msg = '%s - - [%s] %s' % (
                self.address_string(),
                self.log_date_time_string(),
                message % args,
            )
            http_code = str(args[1])
        except:
            return _orig_log(type, message, *args)

        # Utilize terminal colors, if available
        if http_code[0] == '2':
            # Put 2XX first, since it should be the common case
            msg = _style.HTTP_SUCCESS(msg)
        elif http_code[0] == '1':
            msg = _style.HTTP_INFO(msg)
        elif http_code == '304':
            msg = _style.HTTP_NOT_MODIFIED(msg)
        elif http_code[0] == '3':
            msg = _style.HTTP_REDIRECT(msg)
        elif http_code == '404':
            msg = _style.HTTP_NOT_FOUND(msg)
        elif http_code[0] == '4':
            msg = _style.HTTP_BAD_REQUEST(msg)
        else:
            # Any 5XX, or any other response
            msg = _style.HTTP_SERVER_ERROR(msg)

        _log(type, msg)

    WSGIRequestHandler.log = werk_log
