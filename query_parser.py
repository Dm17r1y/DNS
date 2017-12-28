#!/usr/bin/python3

import struct
from enum import Enum


class QueryType(Enum):
    Request = 0
    Response = 1


class QueryOpcode(Enum):
    StandartQuery = 0
    InverseQuery = 1
    StatusQuery = 2


class QueryReplyCode(Enum):
    NoError = 0
    ServerFailure = 2
    NameError = 3


class RecordType(Enum):
    Ipv4 = 1
    Ipv6 = 28
    DnsServer = 2
    CanonicName = 5
    Pointer = 12
    MailExchanger = 15
    ServerOfAuthority = 6

    def __str__(self):
        tags = {
            RecordType.Ipv4: "A",
            RecordType.Ipv6: "AAAA",
            RecordType.DnsServer: "NS",
            RecordType.CanonicName: "CNAME",
            RecordType.Pointer: "PTR",
            RecordType.MailExchanger: "MX",
            RecordType.ServerOfAuthority: "SOA"
        }
        return tags[self]


class IPV4Address:

    def __init__(self, raw_address):
        self.raw_address = raw_address

    def __str__(self):
        address = []
        for i in range(4):
            address.append(str(self.raw_address[i]))
        return ".".join(address)

    def get_raw_data(self):
        return self.raw_address


class IPV6Address:

    def __init__(self, raw_address):
        self.raw_address = raw_address

    def __str__(self):
        address = []
        for i in range(0, 16, 2):
            address.append(hex(struct.unpack("!H",
                                             self.raw_address[i:i+2])[0])[2:])
        return ":".join(address)

    def get_raw_data(self):
        return self.raw_address


class MailExchangeName:
    def __init__(self, domain_name, preference):
        self.domain_name = domain_name
        self.preference = preference

    def __str__(self):
        return "{} {}".format(self.preference, self.domain_name)


class DataReader:

    def __init__(self, raw_data):
        self.data = raw_data
        self.position = 0

    def read(self, byte_number):
        return_data = self.data[self.position:self.position + byte_number]
        self.position += byte_number
        return return_data

    @staticmethod
    def _create_data_reader(data, offset):
        data_reader = DataReader(data)
        data_reader.position = offset
        return data_reader

    def read_domain_name(self):
        words = []
        next_word_len = struct.unpack("!B", self.read(1))[0]
        while next_word_len != 0:
            if next_word_len & 0xc0 == 0xc0:
                domain_name_offset = next_word_len & 0x3f << 8 | \
                                     struct.unpack("!B", self.read(1))[0]
                new_data_reader = self._create_data_reader(self.data,
                                                           domain_name_offset)
                for word in new_data_reader.read_domain_name():
                    words.append(word)
                break
            else:
                words.append(self.read(next_word_len).decode())
                next_word_len = struct.unpack("!B", self.read(1))[0]
        return words


class Query:

    class QueryFlags:

        def __init__(self, raw_flags):
            self.type = QueryType((raw_flags & 0x8000) >> 15)
            self.opcode = QueryOpcode((raw_flags & 0x7800) >> 11)
            self.authority_answer = bool((raw_flags & 0x400) >> 10)
            self.truncated = bool((raw_flags & 0x200) >> 9)
            self.recursion_desired = bool((raw_flags & 0x100) >> 8)
            self.recursion_available = bool((raw_flags & 0x80) >> 7)
            self.reply_code = QueryReplyCode((raw_flags & 0xf))

        def __str__(self):
            return "[type: {}, opcode: {}, is authority: {}, truncated: {}, " \
                   "recursion desired: {}, recursion available: {}, " \
                   "reply code: {}]".format(
                        self.type.value, self.opcode.value,
                        self.authority_answer,
                        self.truncated, self.recursion_desired,
                        self.recursion_available, self.reply_code.value
                    )

        @staticmethod
        def get_flags(query_type, recursion_desired):
            return Query.QueryFlags(query_type.value << 15 |
                                    int(recursion_desired) << 8)

        def get_raw_flags(self):
            return self.type.value << 15 | self.opcode.value << 11 | \
                   self.authority_answer << 10 | self.truncated << 9 | \
                   self.recursion_desired << 8 | \
                   self.recursion_available << 7 | \
                   self.reply_code.value

    class Question:

        def __init__(self, name, type):
            self.name = name
            self.type = type

        def __str__(self):
            return "name: {}, type: {}".format(self.name, self.type)

        def get_raw_data(self):
            return Query.encode_domain_name(self.name) + \
                   struct.pack("!HH", self.type.value, 1)

    class Record:

        def __init__(self, name, address_type, time_to_live, data):
            self.name = name
            self.type = address_type
            self.time_to_live = time_to_live
            self.data = data

        def __str__(self):
            return "name: {}, type: {}, time to live: {}, data: {}".format(
                self.name, self.type, self.time_to_live, self.data
            )

        def get_raw_data(self):
            if self.type == RecordType.DnsServer:
                raw_data = Query.encode_domain_name(self.data)
            else:
                raw_data = self.data.get_raw_data()
            return Query.encode_domain_name(self.name) + struct.pack(
                "!HHIH", self.type.value, 1, self.time_to_live, len(raw_data)
            ) + raw_data

    HEADER_STRUCTURE = ">6H"

    def __init__(self, query_id, flags, questions, answers,
                 authorities, additional):
        self.id = query_id
        self.flags = flags
        self.questions = questions
        self.answers = answers
        self.authorities = authorities
        self.additional = additional

    @staticmethod
    def encode_domain_name(name):
        words = name.split('.')
        bytes_ = b""
        for word in words:
            byte_word = word.encode()
            bytes_ += struct.pack("!B", len(byte_word)) + byte_word
        return bytes_ + b"\x00"

    def get_raw_bytes(self):
        raw_flags = self.flags.get_raw_flags()
        header = struct.pack(self.HEADER_STRUCTURE, self.id, raw_flags,
                             len(self.questions), len(self.answers),
                             len(self.authorities), len(self.additional))
        data = b""
        for records in (self.questions, self.answers, self.authorities,
                        self.additional):
            for record in records:
                data += record.get_raw_data()
        return header + data

    @staticmethod
    def get_query_information(raw_data):

        def read_questions(data_reader, number_of_questions):
            questions = []
            for i in range(number_of_questions):
                domain_name = ".".join(data_reader.read_domain_name())
                question_type, question_class = \
                    struct.unpack("!HH", data_reader.read(4))
                questions.append(Query.Question(domain_name,
                                                RecordType(question_type)))
            return questions

        def read_records(data_reader, number_of_records):
            records = []
            for i in range(number_of_records):
                domain_name = ".".join(data_reader.read_domain_name())
                record_type, record_class, time_to_live, data_length = \
                    struct.unpack("!HHIH", data_reader.read(10))
                record_type = RecordType(record_type)
                if record_type == RecordType.DnsServer:
                    data = ".".join(data_reader.read_domain_name())
                elif record_type == RecordType.MailExchanger:
                    preference = struct.unpack("!H", data_reader.read(2))[0]
                    domain = ".".join(data_reader.read_domain_name())
                    data = MailExchangeName(domain, preference)
                elif record_type == RecordType.Ipv4:
                    data = IPV4Address(data_reader.read(data_length))
                elif record_type == RecordType.Ipv6:
                    data = IPV6Address(data_reader.read(data_length))
                else:
                    data = data_reader.read(data_length)

                records.append(Query.Record(domain_name, record_type,
                                            time_to_live, data))
            return records

        data_reader = DataReader(raw_data)
        identification, flags, question_number, answer_number, \
            authority_fields_number, additional_fields_number = \
            struct.unpack(Query.HEADER_STRUCTURE, data_reader.read(12))

        query_flags = Query.QueryFlags(flags)

        questions = read_questions(data_reader, question_number)
        answers = read_records(data_reader, answer_number)
        authority = read_records(data_reader, authority_fields_number)
        additional = read_records(data_reader, additional_fields_number)

        return Query(identification, query_flags, questions, answers,
                     authority, additional)
