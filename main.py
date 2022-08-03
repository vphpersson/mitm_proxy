#!/usr/bin/env python

from __future__ import annotations
from logging import Logger, getLogger, StreamHandler, INFO, WARNING
from typing import Generator, NewType
from asyncio import run as asyncio_run, start_server, StreamReader, StreamWriter, TimeoutError, gather as asyncio_gather
from functools import partial
from ipaddress import IPv4Address, IPv6Address
from sys import stderr
from contextlib import aclosing

from http_lib.parse.host import parse_host, IPvFutureString
from http_lib.parse.header.connection import parse_connection
from http_lib.structures.message import message_parts_from_reader, RequestLine, headers_from_bytes, Request, Response, \
    StatusLine
from abnf_parse.rulesets.rfc9112 import RFC9112_RULESET
from abnf_parse.exceptions import NoMatchError
from ecs_tools_py import make_log_handler

from mitm_proxy.structures.connection import Connection, LOG as CONNECTION_LOG
from mitm_proxy.crypto import CertificateAuthority, make_non_signed_x509_certificate, make_rsa_pair
from mitm_proxy import tls_handshake

handler = make_log_handler(base_class=StreamHandler)(stream=stderr)

LOG: Logger = getLogger(__name__)
LOG.addHandler(hdlr=handler)
LOG.setLevel(level=WARNING)

CONNECTION_LOG.addHandler(hdlr=handler)
CONNECTION_LOG.setLevel(level=INFO)

TIMEOUT = 15

Headers = NewType(name='Headers', tp=list[tuple[str, str]])


def _get_keep_alive(headers: Headers) -> tuple[bool, list[str]]:

    if connection_value := next((value for key, value in headers if key.lower() == 'connection'), None):
        connection_options = parse_connection(connection_value=connection_value)
    else:
        connection_options = ['keep-alive']

    match connection_options[0].lower():
        case 'keep-alive':
            keep_alive = True
        case 'close':
            keep_alive = False
        case _:
            raise ValueError('Bad connection option.')

    return keep_alive, connection_options


async def _request(
    reader: StreamReader,
    timeout: float | None = None
) -> Generator[RequestLine | Headers | bytes, None, None]:

    request_parts_generator = message_parts_from_reader(reader=reader, timeout=timeout)

    request_line_memoryview = memoryview(await anext(request_parts_generator))
    request_line = RequestLine.from_bytes(data=request_line_memoryview[:-2])

    yield request_line

    request_header_bytes: bytes = await anext(request_parts_generator)
    headers: list[tuple[str, str]] = headers_from_bytes(data=request_header_bytes)

    yield headers

    await request_parts_generator.asend(headers)

    request_keep_alive, connection_options = _get_keep_alive(headers=headers)

    try:
        first_body_part = await anext(request_parts_generator)
    except StopAsyncIteration:
        first_body_part = b''

    # TODO: Remove headers listed in the connection header?

    yield request_line_memoryview.tobytes() + request_header_bytes + first_body_part

    if not request_keep_alive:
        return

    async for body_part in request_parts_generator:
        yield body_part


def _obtain_host_and_port(request_line: RequestLine, headers: Headers) -> tuple[str | IPv4Address | IPv6Address, int]:

    host: str | IPv4Address | IPv6Address | IPvFutureString
    port: int | None

    match request_line.method.upper():
        case 'CONNECT':
            request_target = RFC9112_RULESET['request-target'].evaluate(source=request_line.request_target.encode())

            request_target_form_node = request_target.children[0]
            if request_target_form_node.name != 'authority-form':
                raise ValueError('The request target does not have the authority form.')

            # The ABNF definitions of `authority-form` and `Host` are the same apart from the colon and port being
            # optional for `Host`.
            host, port = parse_host(host_value=request_target_form_node.get_value())
        case _:
            host, port = parse_host(
                host_value=next(value.encode() for (key, value) in headers if key.lower() == 'host')
            )

    if isinstance(host, IPvFutureString):
        raise NotImplementedError('IPvFuture hosts are not supported.')

    port = port or 80

    return host, port


async def handle_proxy_connection(proxy_connection: Connection, client_connection: Connection, req_iter):

    request_body_buffer = bytearray()
    response_body_buffer = bytearray()

    async with aclosing(req_iter):
        first_request_body_part: bytes = await anext(req_iter)
        request_body_buffer += first_request_body_part

        proxy_connection.writer.write(first_request_body_part)
        await proxy_connection.writer.drain()

        async def from_client():
            nonlocal request_body_buffer

            try:
                async for request_body_data in req_iter:
                    request_body_buffer += request_body_data
                    client_connection.writer.write(request_body_data)
                    await client_connection.writer.drain()
            except TimeoutError:
                pass

            client_connection.request.body = memoryview(request_body_buffer)

        async def from_server():
            response_parts_generator = message_parts_from_reader(reader=proxy_connection.reader, timeout=TIMEOUT)

            status_line_bytes = await anext(response_parts_generator)

            response_header_bytes = await anext(response_parts_generator)
            response_headers: Headers = headers_from_bytes(data=response_header_bytes)

            response_keep_alive, connection_options = _get_keep_alive(headers=response_headers)

            await response_parts_generator.asend(response_headers)

            try:
                first_response_body_part = await anext(response_parts_generator)
            except StopAsyncIteration:
                first_response_body_part = b''

            nonlocal response_body_buffer
            response_body_buffer += first_response_body_part

            client_connection.writer.write(status_line_bytes + response_header_bytes + first_response_body_part)
            await client_connection.writer.drain()

            if not response_keep_alive:
                return

            try:
                async for response_body_part in response_parts_generator:
                    response_body_buffer += response_body_part
                    client_connection.writer.write(response_body_part)
                    await client_connection.writer.drain()
            except TimeoutError:
                pass

            client_connection.response = Response.from_bytes(
                data=status_line_bytes + response_header_bytes + response_body_buffer
            )

        await asyncio_gather(from_server(), from_client())

        client_connection.log()


async def handle_connection(client_connection: Connection, certificate_authority: CertificateAuthority):

    async with aclosing(_request(reader=client_connection.reader)) as req_iter:
        try:
            request_line: RequestLine = await anext(req_iter)
        except:
            LOG.exception(
                msg='An error occurred when attempting to obtain the initial request line.',
                extra=client_connection.get_metadata()
            )
            return

        try:
            headers: Headers = await anext(req_iter)
        except:
            LOG.exception(
                msg='An error occurred when attempting to obtain the initial request headers.',
                extra=client_connection.get_metadata()
            )
            return

        host: str | IPv4Address | IPv6Address
        port: int
        host, port = _obtain_host_and_port(request_line=request_line, headers=headers)

        setup_ssl = request_line.method.upper() == 'CONNECT'

        proxy_connection = await Connection.make_proxy_connection(
            host=str(host),
            port=port,
            use_ssl=setup_ssl,
            name='proxy'
        )

        async with proxy_connection:
            if setup_ssl:
                status_line = StatusLine(http_version='HTTP/1.1', status_code=200, reason_phrase='OK')
                client_connection.writer.write(data=bytes(status_line) + b'\r\n\r\n')
                await client_connection.writer.drain()

                client_connection.request = Request(start_line=request_line, headers=headers, body=memoryview(b''))
                client_connection.response = Response(start_line=status_line)
                client_connection.log()

                # Generates a new context specific to the host.
                ssl_context = certificate_authority.new_context(host=host)

                # Perform handshake.
                await tls_handshake(
                    reader=client_connection.reader,
                    writer=client_connection.writer,
                    ssl_context=ssl_context,
                    server_side=True,
                )

                req_iter = _request(reader=client_connection.reader)
                try:
                    request_line = await anext(req_iter)
                except NoMatchError as e:
                    LOG.exception(
                        msg='The request line is not in a valid format.',
                        extra=client_connection.get_metadata() | dict(source=e.source.tobytes().decode())
                    )
                    return

                headers = await anext(req_iter)

            client_connection.request = Request(start_line=request_line, headers=headers)
            client_connection.response = None

            await handle_proxy_connection(
                proxy_connection=proxy_connection,
                client_connection=client_connection,
                req_iter=req_iter
            )


async def handle(client_reader: StreamReader, client_writer: StreamWriter, certificate_authority: CertificateAuthority):
    async with Connection(reader=client_reader, writer=client_writer, name='client') as connection:
        try:
            await handle_connection(client_connection=connection, certificate_authority=certificate_authority)
        except ConnectionResetError as e:
            LOG.warning(msg='A connection was reset.', exc_info=e, extra=connection.get_metadata())
        except ConnectionRefusedError as e:
            LOG.warning(msg='A connection was refused.', exc_info=e, extra=connection.get_metadata())
        except:
            LOG.exception(msg='An error occurred while handling a client connection.', extra=connection.get_metadata())


async def main():

    cert_path = 'mitm.crt'
    key_path = 'mitm.key'

    host = '127.0.0.1'
    port = 8888

    try:
        certificate_authority = CertificateAuthority.from_path(cert_path=cert_path, key_path=key_path)
    except:
        certificate_authority = CertificateAuthority(
            key=make_rsa_pair(),
            cert=make_non_signed_x509_certificate()
        )

    certificate_authority.save(cert_path=cert_path, key_path=key_path)

    start_server_options = dict(
        client_connected_cb=partial(handle, certificate_authority=certificate_authority),
        host=host,
        port=port
    )
    async with await start_server(**start_server_options) as server:
        await server.serve_forever()

if __name__ == '__main__':
    asyncio_run(main())
