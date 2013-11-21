import re
import dns
from dns import resolver
from netaddr import *


class SPFCheck:
    """
    Checking SPF status. Compatible with SPF and SenderID. (Spf v2)

    @Usage:
    Use the verify function with ip and domain. Note that SenderID is considered version 2.
    """

    _logger = None

    def ___init__(cls, logger=None):
        """ Init the class with an optionnal logger"""

        if logger is not None:
            cls._logger = logger

    def verify(cls, ip, domain, version=1):
        """
        Verify the SPF state of an IP and a domain.

        @parameters
        ip -- IP Address to check.
        domain -- Sending domain to check.
        version -- SPF version (1 spf, 2 SenderID) -- Default 1
        """

        if cls._logger is not None:
            cls._logger.info('Checking %s and %s with version %i' % (domain, ip, version))

        try:
            txt_list =  cls.gather_txt(domain)
        except dns.resolver.NXDOMAIN:
            return ('PermError', 'No DNS record for the specified domain.')
        except dns.resolver.NoAnswer:
            return ('TempError', 'No anwser from DNS record.')
        except dns.exception.Timeout:
            return ('PermError', 'DNS record timeout for the specified domain.')
        except Exception, e:
            if cls._logger is not None:
                cls._logger.critcal("Error during spf process.")
            raise e

        spf = cls.gather_spf(txt_list, version)
        if spf:
            try:
                result = cls.process_spf(spf, ip, domain)
            except dns.resolver.NXDOMAIN:
                return ('PermError', 'No DNS record for the specified domain.')
            except dns.resolver.NoAnswer:
                return ('TempError', 'No anwser from DNS record.')
            except Exception, e:
                if cls._logger is not None:
                    cls._logger.critcal("Error during spf process.")
                raise e
            else:
                return result

    def gather_txt(cls, domain):
        """ Basic DNS TXT query for the domain domain. """

        try:
            answers = resolver.query(domain, 'TXT')
        except Exception, e:
            if cls._logger is not None:
                cls._logger.critcal("Error during DNS query.")
            raise e
        else:
            txt = ["".join(rdata.strings) for rdata in answers]
            return  txt

    def gather_spf(cls, txt_list, version):
        """
        Parse a TXT response field to gather spf.

        @parameters
        txt_list: List of all the txt responses.
        version: SPF version to parse.
        """

        if version == 1:
            reg = re.compile("^(v=spf1) (.*)")
        elif version == 2:
            reg = re.compile("^(spf2.0/pra) (.*)")
        else:
            raise Exception("SPF Version not supported.")

        for txt in txt_list:
            match = reg.match(txt)
            if match:
                return match.group(2)
        return False

    def process_spf(cls, spf, ip, domain, inc_index=0):
        rules_list = []
        for rule in spf.split(' '):
            if rule[0] not in ['+', '?', '-', '~']:
                rule = '+%s' % rule
            result = cls.process_rule(rule, ip, domain, inc_index)
            if result:
                return result
        return ('None', '%s does not match any rules.' % ip)

    def process_rule(cls, rule, ip, domain, inc_index):
        actions_list = {
            '+': 'Pass',
            '-': 'Fail',
            '~': 'SoftFail',
            '?': 'Neutral'
        }

        # Extract action
        action = actions_list[rule[:1]]
        rule = rule[1:]

        if cls._logger is not None:
            cls._logger.debug("Action=%s for Rule=%s" % (action, rule))

        if rule[:3] == 'ip4':  #IP Address
            if "/" in rule[4:]:  #Subnet
                network = IPNetwork(rule[4:])
                if IPAddress(ip) in list(network):
                    return (action, "%s match rule %s" % (ip, rule))
            if ip == rule[4:]:
                return (action, "%s match rule %s" % (ip, rule))
        elif rule[:1] == 'a' and rule[:3] == 'all':
            reg = re.match('^a:?(?P<domain>[\w\d\.]+)?/?(?P<prefix_length>[\d]{1,2})?', rule)
            if reg.group('domain') is not None:
                domain = reg.group('domain')
            prefix_length = reg.group('prefix_length')

            # Retrieve A record.
            try:
                answers = resolver.query(domain, 'A')
            except Exception, e:
                raise e
            else:
                for rdata in answers:
                    if prefix_length is not None:
                        ip_network = IPNetwork(str(rdata)+"/"+prefix_length)
                        if IPAddress(ip) in list(ip_network):
                            return (action, "%s match rule %s" % (ip, rule))
                    else:
                        if ip == str(rdata):
                            return (action, "%s match rule %s" % (ip, rule))
        elif rule[:2] == 'mx':
            reg = re.match('^mx:?(?P<domain>[\w\d\.]+)?/?(?P<prefix_length>[\d]{1,2})?', rule)
            if reg.group('domain') is not None:
                domain = reg.group('domain')
            prefix_length = reg.group('prefix_length')

            # Retrieve MX record
            try:
                answers = resolver.query(domain, 'MX')
            except Exception, e:
                if cls._logger is not None:
                    cls._logger.critcal("Error during DNS Query.")
                raise e
            else:
                mx_list = []
                for rdata in answers:
                    mx_list.append((rdata.preference, str(rdata.exchange)))
                mx_list.sort(key=lambda tup: tup[0], reverse=True)

                # Test a of all domains.
                for d in mx_list:
                    try:
                        answers = resolver.query(d[1], 'A')
                    except Exception, e:
                        if cls._logger is not None:
                            cls._logger.critcal("Error during DNS Query.")
                        raise e
                    else:
                        for rdata in answers:
                            if prefix_length is not None:
                                ip_network = IPNetwork(str(rdata)+"/"+prefix_length)
                                if IPAddress(ip) in list(ip_network):
                                    return (action, "%s match rule %s" % (ip, rule))
                            else:
                                if ip == str(rdata):
                                    return (action, "%s match rule %s" % (ip, rule))
        elif rule[:3] == 'ptr':
            reg = re.match('^ptr:?(?P<domain>[\w\d\.]+)?', rule)
            if reg.group('domain') is not None:
                domain = reg.group('domain')
            # PTR query.
            domains_list = []
            try:
                answers = resolver.query(dns.reversename.from_address(ip), 'PTR')
            except Exception, e:
                if cls._logger is not None:
                    cls._logger.critcal("Error during DNS Query.")
                raise e
            else:
                for returned_domain in answers:
                    try:
                        answers = resolver.query(str(returned_domain), 'A')
                    except Exception, e:
                        raise e
                    else:
                        for returned_ip in answers:
                            if str(returned_ip) == ip:
                                domains_list.append(str(returned_domain))

            for d in domains_list:
                if d[(len(d)-1)-len(domain):-1] == domain:
                    return (action, "%s match rule %s" % (ip, rule))
        elif rule[:6] == "exists":
            reg = re.match('^exists:?(?P<domain>[\w\d\.]+)?', rule)
            if reg.group('domain') is not None:
                domain = reg.group('domain')
                try:
                    answers = resolver.query(domain, 'A')
                except Exception, e:
                    if cls._logger is not None:
                        cls._logger.critcal("Error during DNS Query.")
                    raise e
                else:
                    for returned_ip in answers:
                        return (action, "%s match rule %s" % (domain, rule))
        elif rule[:7] == "include":
            if cls._logger is not None:
                cls._logger.debug("Checking include %s with level %i" % (rule, inc_index))
            # Increase spf level
            inc_index += 1

            if inc_index < 11:
                reg = re.match('^include:?(?P<domain>[\w\d\.]+)?', rule)
                if reg.group('domain') is not None:
                    domain = reg.group('domain')
                    txt_list =  cls.gather_txt(domain)
                    spf = cls.gather_spf(txt_list, version=1)

                    if spf:
                        try:
                            result = cls.process_spf(spf, ip, domain, inc_index)
                        except Exception, e:
                            if cls._logger is not None:
                                cls._logger.critcal("Error during DNS Query.")
                            print e
                        else:
                            if result[0] != "None":
                                return result
            else:
                raise Exception("SPF Loop, more than 11 includes level.")
        elif rule == 'all':
            if inc_index == 0:
                if action != 'Pass':
                    return (action, "%s does not match any rules" % ip)
                else:
                    return (action, "%s match rule %s" % (ip, rule))
        else:
            raise Exception('Rule %s is not managed.' % rule)
        return False
