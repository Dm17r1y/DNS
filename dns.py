#!/usr/bin/python3

from dns_servers import dns_root_servers
from query_parser import *
import socket
import random

QUERY_ID = 31337
UDP_PORT = 53
DEFAULT_TIMEOUT = 2
ALLOW_IPV6 = False


class Domain:

    class Address:

        def __init__(self, address, address_type):
            self.address = address
            self.type = address_type

        def __str__(self):
            return 'address: ' + self.address + ', type: ' + str(self.type)

    def __init__(self, name, addresses=None):
        self.name = name.lower()
        if addresses is None:
            addresses = []
        self.addresses = addresses
        self.responsible_domain = None

    def add_address(self, address):
        self.addresses.append(address)

    def __str__(self):
        return self.name + ': [' + ", ".join(str(addr)
                                             for addr in self.addresses) + ']'


class EmptyDebugClass:

    def send_debug_function(self, address):
        pass

    def recv_debug_function(self, queries):
        pass


class DNS:

    class Socket:
        def __init__(self, tcp_mode, timeout):
            self._tcp_mode = tcp_mode
            self._timeout = timeout
            if tcp_mode:
                self._socket = None
            else:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._socket.settimeout(timeout)

        def send(self, raw_data, address, port):
            if self._tcp_mode:
                self._socket = socket.socket()
                self._socket.settimeout(self._timeout)
                self._socket.connect((address, port))
                raw_data = struct.pack("!H", len(raw_data)) + raw_data
                self._socket.send(raw_data)
            else:
                self._socket.sendto(raw_data, (address, port))

        def recv(self):
            data = self._socket.recv(1000)
            if self._tcp_mode:
                return data[2:]
            return data

    def __init__(self, root_server=None, port=UDP_PORT,
                 is_recursion_desired=False, timeout=DEFAULT_TIMEOUT,
                 debug_class=None, tcp=False):
        self.socket = DNS.Socket(tcp, timeout)
        self.root_server = root_server if root_server \
            else random.choice(dns_root_servers)
        self.port = port
        self.debug_class = debug_class if debug_class \
            else EmptyDebugClass()
        self.recursion = is_recursion_desired

    def get_answers(self, domain, record_type):
        query = self._generate_query_request(domain, record_type)
        server_address = self.root_server
        self._send_query(query, server_address)
        responses = self.get_response()
        answers, authorities, additional = self._parse_responses(responses)
        while len(answers) == 0:
            ips = self._get_ips(authorities, additional, domain, record_type)
            server_address = random.choice(ips)
            self._send_query(query, server_address)
            responses = self.get_response()
            answers, authorities, additional = self._parse_responses(responses)
        return answers

    def _parse_responses(self, responses):
        answers = []
        authorities = []
        additional = []
        for response in responses:
            for record in response.answers:
                answers.append(record)
            for record in response.authorities:
                authorities.append(record)
            for record in response.additional:
                additional.append(record)
        return answers, authorities, additional

    @staticmethod
    def _can_connect_by_this_type(record_type):
        return record_type == RecordType.Ipv4 or \
               (record_type == RecordType.Ipv6 and ALLOW_IPV6)

    def _get_ips(self, authorities, additional, domain, record_type):

        def is_authoritative_domain(domain, name):
            domain_parts = domain.split(".")
            domain_parts.reverse()
            name_parts = name.split(".")
            name_parts.reverse()
            for first, second in zip(domain_parts, name_parts):
                if first != second:
                    return False
            return True

        def find_authoritative_servers(authorities, additional, domain):
            authoritative_server_names = set()
            for record in authorities:
                if record.type == RecordType.DnsServer and \
                        is_authoritative_domain(record.name.lower(), domain):
                    authoritative_server_names.add(record.data.lower())
            authoritative_servers_ips = []
            for record in additional:
                if DNS._can_connect_by_this_type(record.type) and \
                        record.name.lower() in authoritative_server_names:
                    authoritative_servers_ips.append(record.data)
            return authoritative_server_names, authoritative_servers_ips

        names, ips = find_authoritative_servers(authorities, additional,
                                                domain)

        if len(ips) == 0:
            if len(names) == 0:
                raise Exception("{} has no {} record".format(
                    domain, record_type
                ))
            domain_name = random.choice(list(names))
            answers = self.get_answers(domain_name, RecordType.Ipv4)
            ips = [answer.data for answer in answers
                   if answer.type == RecordType.Ipv4]

        return ips

    def _send_query(self, query, address):
        query_bytes = query.get_raw_bytes()
        self.debug_class.send_debug_function(str(address))
        self.socket.send(query_bytes, str(address), self.port)

    def get_response(self):
        queries = []
        data = self.socket.recv()
        query = Query.get_query_information(data)
        queries.append(query)
        while query.flags.truncated:
            data = self.socket.recv()
            query = Query.get_query_information(data)
            queries.append(query)
        self.debug_class.recv_debug_function(queries)
        return queries

    def _generate_query_request(self, domain_name, record_type):
        flags = Query.QueryFlags.get_flags(QueryType.Request, self.recursion)
        question = Query.Question(domain_name, record_type)
        return Query(QUERY_ID, flags, [question], [], [], [])
