import ssl
import socks
from imaplib import IMAP4


class Imap4Proxy(IMAP4):
    def __init__(self,
                 host: str = "",
                 port: int = 143,
                 p_timeout: int = None,
                 p_proxy_type: socks.PROXY_TYPES = socks.HTTP,
                 p_proxy_addr: str = None,
                 p_proxy_port: int = None,
                 p_proxy_rdns=True,
                 p_proxy_username: str = None,
                 p_proxy_password: str = None,
                 p_socket_options: iter = None,
                 ):
        self._host = host
        self._port = port
        self._p_timeout = p_timeout
        self._p_proxy_type = p_proxy_type
        self._p_proxy_addr = p_proxy_addr
        self._p_proxy_port = p_proxy_port
        self._p_proxy_rdns = p_proxy_rdns
        self._p_proxy_username = p_proxy_username
        self._p_proxy_password = p_proxy_password
        self._p_socket_options = p_socket_options
        super().__init__(host, port)

    def _create_socket(self, timeout=None):
        return socks.create_connection(
            dest_pair=(self._host, self._port),
            timeout=self._p_timeout,
            proxy_type=self._p_proxy_type,
            proxy_addr=self._p_proxy_addr,
            proxy_port=self._p_proxy_port,
            proxy_rdns=self._p_proxy_rdns,
            proxy_username=self._p_proxy_username,
            proxy_password=self._p_proxy_password,
            socket_options=self._p_socket_options,
        )


class Imap4SslProxy(Imap4Proxy):
    def __init__(self,
                 host: str = "",
                 port: int = 993,
                 keyfile=None,
                 certfile=None,
                 ssl_context=None,
                 p_timeout: int = None,
                 p_proxy_type: socks.PROXY_TYPES = socks.HTTP,
                 p_proxy_addr: str = None,
                 p_proxy_port: int = None,
                 p_proxy_rdns=True,
                 p_proxy_username: str = None,
                 p_proxy_password: str = None,
                 p_socket_options: iter = None,
                 ):
        self._host = host
        self._port = port
        self._p_timeout = p_timeout
        self._p_proxy_type = p_proxy_type
        self._p_proxy_addr = p_proxy_addr
        self._p_proxy_port = p_proxy_port
        self._p_proxy_rdns = p_proxy_rdns
        self._p_proxy_username = p_proxy_username
        self._p_proxy_password = p_proxy_password
        self._p_socket_options = p_socket_options

        if ssl_context is not None and keyfile is not None:
            raise ValueError("ssl_context and keyfile arguments are mutually exclusive")
        if ssl_context is not None and certfile is not None:
            raise ValueError("ssl_context and certfile arguments are mutually exclusive")
        if keyfile is not None or certfile is not None:
            import warnings
            warnings.warn("keyfile and certfile are deprecated, use ssl_context instead", DeprecationWarning, 2)

        if ssl_context is None:
            ssl_context = ssl._create_stdlib_context(certfile=certfile, keyfile=keyfile)  # noqa

        self.keyfile = keyfile
        self.certfile = certfile
        self.ssl_context = ssl_context

        super().__init__(host, port, p_timeout, p_proxy_type, p_proxy_addr, p_proxy_port,
                         p_proxy_rdns, p_proxy_username, p_proxy_password, p_socket_options)

    def _create_socket(self, timeout=None):
        sock = super()._create_socket()
        server_hostname = self.host if ssl.HAS_SNI else None
        return self.ssl_context.wrap_socket(sock, server_hostname=server_hostname)

    def open(self, host='', port=993, timeout=None):  # noqa
        super().open(host, port)
