from asyncio import StreamReader, StreamWriter, get_event_loop
from ssl import SSLContext, create_default_context


async def tls_handshake(
    reader: StreamReader,
    writer: StreamWriter,
    ssl_context: SSLContext | None = None,
    server_side: bool = False,
) -> None:
    """
    Manually perform a TLS handshake over a stream.

    :param reader:
    :param writer:
    :param ssl_context:
    :param server_side:
    :return: None
    """

    if not server_side and not ssl_context:
        ssl_context = create_default_context()

    transport = writer.transport
    protocol = transport.get_protocol()

    loop = get_event_loop()
    new_transport = await loop.start_tls(
        transport=transport,
        protocol=protocol,
        sslcontext=ssl_context,
        server_side=server_side,
    )

    reader._transport = new_transport
    writer._transport = new_transport
