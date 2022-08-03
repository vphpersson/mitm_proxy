from __future__ import annotations
from logging import Logger, getLogger
from dataclasses import dataclass
from typing import Any
from asyncio import StreamReader, StreamWriter, open_connection

from ecs_py import Base, Source, Network
from ecs_tools_py import network_entry_from_socket, entry_from_http_message, merge_ecs_entries
from http_lib.structures.message import Request, Response

LOG: Logger = getLogger(__name__)


@dataclass
class Connection:
    reader: StreamReader
    writer: StreamWriter
    source_ip: str | None = None
    source_port: int | None = None
    type: str | None = None
    transport: str | None = None
    name: str | None = None

    request: Request | None = None
    response: Response | None = None

    def __post_init__(self):
        peer_name = self.writer.get_extra_info(name='peername')
        if not peer_name:
            LOG.warning(msg='Unable to obtain peername for a connection.')
        else:
            self.source_ip, self.source_port = peer_name

        if not (socket := self.writer.get_extra_info('socket')):
            LOG.warning(msg='Unable to obtain the socket for a connection.', extra=self.get_metadata())
        else:
            socket_network_entry = network_entry_from_socket(socket=socket)
            self.type = socket_network_entry.type
            self.transport = socket_network_entry.transport

    @classmethod
    async def make_proxy_connection(cls, host: str, port: int, use_ssl: bool, name: str | None = None) -> Connection:
        reader, writer = await open_connection(host=host, port=port, ssl=use_ssl)
        return cls(reader=reader, writer=writer, name=name)

    def get_metadata(self) -> dict[str, Any]:
        return dict(
            source_ip=self.source_ip,
            source_port=self.source_port,
            type=self.type,
            transport=self.transport,
            connection_name=self.name
        )

    def log(self):
        base_entry: Base = entry_from_http_message(http_message=self.request, use_host_header=True)

        if self.response:
            base_entry = merge_ecs_entries(base_entry, entry_from_http_message(http_message=self.response))

        source_namespace: Source = base_entry.get_field_value(field_name='source', create_namespaces=True)
        source_namespace.ip = source_namespace.address = self.source_ip
        source_namespace.port = self.source_port

        client_namespace: Source = base_entry.get_field_value(field_name='client', create_namespaces=True)
        client_namespace.ip = client_namespace.address = self.source_ip
        client_namespace.port = self.source_port

        network_namespace: Network = base_entry.get_field_value(field_name='network', create_namespaces=True)
        network_namespace.type = self.type
        network_namespace.transport = self.transport

        LOG.info(msg='An HTTP transaction occurred.', extra=base_entry.to_dict())

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception as e:
            if isinstance(e, GeneratorExit):
                raise e

            LOG.exception(
                msg='An error occurred when attempting to close the connection\'s writer.',
                extra=self.get_metadata()
            )
