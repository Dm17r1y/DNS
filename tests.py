#!/usr/bin/python3

import unittest
from query_parser import *


class ParseResponseTests(unittest.TestCase):

    def setUp(self):

        self.request_bytes = [
            0xdc, 0x78, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
            0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01
        ]

        self.response_bytes = [
            0xdc, 0x78, 0x81, 0x80, 0x00, 0x01, 0x00, 0x05,
            0x00, 0x00, 0x00, 0x00, 0x03, 0x77, 0x77, 0x77,
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
            0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
            0x00, 0xf8, 0x00, 0x04, 0xad, 0xc2, 0x20, 0xf3,
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
            0x00, 0xf8, 0x00, 0x04, 0xad, 0xc2, 0x20, 0xf1,
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
            0x00, 0xf8, 0x00, 0x04, 0xad, 0xc2, 0x20, 0xf4,
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
            0x00, 0xf8, 0x00, 0x04, 0xad, 0xc2, 0x20, 0xf2,
            0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
            0x00, 0xf8, 0x00, 0x04, 0xad, 0xc2, 0x20, 0xf0
        ]

    def test_query_response(self):
        query = Query.get_query_information(bytes(self.response_bytes))
        self.assertEqual(0xdc78, query.id)
        self.assertEqual(1, len(query.questions))
        self.assertEqual(5, len(query.answers))
        self.assertEqual(0, len(query.authorities))
        self.assertEqual(0, len(query.additional))

    def test_response_flags(self):
        query = Query.get_query_information(bytes(self.response_bytes))
        self.assertEqual(QueryType.Response, query.flags.type)
        self.assertEqual(QueryOpcode.StandartQuery,
                         query.flags.opcode)
        self.assertEqual(False, query.flags.authority_answer)
        self.assertEqual(False, query.flags.truncated)
        self.assertEqual(True, query.flags.recursion_desired)
        self.assertEqual(True, query.flags.recursion_available)
        self.assertEqual(QueryReplyCode.NoError, query.flags.reply_code)

    def test_query_request(self):
        query = Query.get_query_information(bytes(self.request_bytes))
        self.assertEqual(0xdc78, query.id)
        self.assertEqual(1, len(query.questions))
        self.assertEqual(0, len(query.answers))
        self.assertEqual(0, len(query.authorities))
        self.assertEqual(0, len(query.additional))

    def test_request_flags(self):
        query = Query.get_query_information(bytes(self.request_bytes))
        self.assertEqual(QueryType.Request, query.flags.type)
        self.assertEqual(QueryOpcode.StandartQuery,
                         query.flags.opcode)
        self.assertEqual(True, query.flags.recursion_desired)

    def test_question(self):
        query = Query.get_query_information(bytes(self.request_bytes))
        question = query.questions[0]
        self.assertEqual("www.google.com", question.name)
        self.assertEqual(RecordType.Ipv4, question.type)

    def test_record(self):
        query = Query.get_query_information(bytes(self.response_bytes))
        answer = query.answers[0]
        self.assertEqual("www.google.com", answer.name)
        self.assertEqual(RecordType.Ipv4, answer.type)
        self.assertEqual(248, answer.time_to_live)
        self.assertEqual("173.194.32.243", str(answer.data))

    def test_get_query_flags(self):
        flags = Query.QueryFlags.get_flags(QueryType.Request, True)
        self.assertEqual(QueryType.Request, flags.type)
        self.assertEqual(QueryOpcode.StandartQuery, flags.opcode)
        self.assertEqual(False, flags.authority_answer)
        self.assertEqual(False, flags.truncated)
        self.assertEqual(True, flags.recursion_desired)
        self.assertEqual(False, flags.recursion_available)
        self.assertEqual(QueryReplyCode.NoError, flags.reply_code)

    def test_generate_query_request(self):
        data = bytes(self.request_bytes)
        query = Query.get_query_information(data)
        new_data = query.get_raw_bytes()
        self.assertEqual(data, new_data)

    def test_MX_records(self):
        pass


if __name__ == "__main__":
    unittest.main()
