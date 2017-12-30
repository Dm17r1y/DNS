#!/usr/bin/python3

import dns
import argparse
from query_parser import RecordType


def main():

    class Debug:
        def send_debug_function(self, address):
            print("send query to " + address)

        def recv_debug_function(self, responses):

            for response in responses:
                print("Response:")
                print("id: {}, flags: {}, questions: {}, answers: {}, "
                      "authority: {}, additional: {}".format(
                          response.id, str(response.flags),
                          len(response.questions),
                          len(response.answers), len(response.authorities),
                          len(response.additional)
                      ))
                print("Questions:")
                for question in response.questions:
                    print(question)
                print("Answers:")
                for answer in response.answers:
                    print(answer)
                print("Authority:")
                for authority in response.authorities:
                    print(authority)
                print("Additional:")
                for additional in response.additional:
                    print(additional)

    parser = argparse.ArgumentParser()
    parser.add_argument('--do_recursive', action='store_true')
    parser.add_argument('--debug', action='store_true')
    parser.add_argument('--tcp', action='store_true')
    parser.add_argument('-type', action='store', dest='type', default="A",
                        choices=["A", "AAAA", "MX", "NS"])
    parser.add_argument('-timeout', action='store', dest='timeout',
                        default=dns.DEFAULT_TIMEOUT, type=int)
    parser.add_argument('domain_name')
    parser.add_argument('server', nargs='?', default=None)
    parser.add_argument('port', nargs='?', type=int, default=dns.UDP_PORT)
    arguments = parser.parse_args()
    debug = Debug() if arguments.debug else None
    dns_class = dns.DNS(is_recursion_desired=arguments.do_recursive,
                        root_server=arguments.server,
                        port=arguments.port, timeout=arguments.timeout,
                        debug_class=debug, tcp=arguments.tcp)
    record_types = {
        "A": RecordType.Ipv4,
        "AAAA": RecordType.Ipv6,
        "MX": RecordType.MailExchanger,
        "NS": RecordType.DnsServer,
    }

    answers = dns_class.get_answers(arguments.domain_name,
                                    record_types[arguments.type])
    for answer in answers:
        print(answer.data)


if __name__ == '__main__':
    main()
