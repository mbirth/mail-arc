#!/usr/bin/env python3
"""Qmail mail validator

This is a script meant to be used in qmail before forwarding mail to e.g. Gmail. It will verify
the incoming mail against SPF, DKIM and more and add the appropriate ARC headers. This makes Gmail
(probably) accept mails for which there's a DMARC rule with "reject" set.

Inspiration taken from http://bazaar.launchpad.net/~dkimpy-hackers/dkimpy/trunk/view/head:/arcsign.py
"""

from __future__ import print_function

__author__ = "Markus Birth"

import os
import re
import socket
import sys

import authres
import authres.arc
import dkim
import spf

AUTHSERV_ID = socket.getfqdn()   # domain or hostname of mail server
AUTHSERV_HOSTNAME = socket.getfqdn()   # full hostname of mail server
DKIM_DOMAIN = b"birth-online.de"
DKIM_SELECTOR = b"mbirth"

# pylint: disable=C0103,C0301

if sys.version_info[0] >= 3:
    # Make sys.stdin and stdout binary streams.
    sys.stdin = sys.stdin.detach()
    sys.stdout = sys.stdout.detach()

privkey = open('/home/mbirth/.dkim-privkey', 'rb').read()

message = sys.stdin.read()

linesep = dkim.util.get_linesep(message)

# Find this line:
# Received: from unknown (sv3-smtp2.lithium.com [208.74.204.9])
#   by eukelade.uberspace.de with SMTP; 23 Jun 2017 18:43:18 -0000

up_srv_ip_match = re.search("Received: from (.*?) \(.*? \[([0-9a-f.:]+)\].*by ", message.decode("utf-8"), re.MULTILINE | re.DOTALL)

#sys.stdout.write(repr(up_srv_ip_match).encode("utf-8"))

if not up_srv_ip_match:
    # Pass-thru message
    sys.stdout.write(message)
    sys.exit(0)

up_srv_helo = up_srv_ip_match.group(1).lower()
up_srv_ip = up_srv_ip_match.group(2)

sender_address = os.getenv('SENDER')

results_list = []

### REV IP LOOKUP

iprev_res = "fail"
iprev_hn = "Lookup error"

try:
    up_srv_hostn = socket.gethostbyaddr(up_srv_ip)
    if up_srv_helo == up_srv_hostn[0]:
        iprev_res = "pass"
        iprev_hn = up_srv_hostn[0]
    else:
        iprev_res = "fail"
except:
    iprev_res = "temperror"

iprev_result = authres.IPRevAuthenticationResult(result=iprev_res, policy_iprev=up_srv_ip, policy_iprev_comment=iprev_hn)
results_list += [iprev_result]

### SPF CHECK

spf_result = spf.check2(i=up_srv_ip, s=sender_address, h=up_srv_helo)
spf_res = authres.SPFAuthenticationResult(result=spf_result[0], smtp_mailfrom=sender_address, smtp_helo=up_srv_helo, reason=spf_result[1])
results_list += [spf_res]

# Write Received-SPF header (must be added ABOVE Received: lines for this server)
sys.stdout.write('Received-SPF: {0} ({1}) receiver={2}; client-ip={3}; helo={4}; envelope-from={5};'.format(spf_result[0], spf_result[1], AUTHSERV_HOSTNAME, up_srv_ip, up_srv_helo, sender_address).encode("utf-8") + linesep)


### ARC SIGNATURE
#import logging
#logging.basicConfig(level=10)
try:
    cv = dkim.CV_None.decode("ascii")
    if re.search(b'arc-seal', message, re.IGNORECASE):
        arc_vrfy = dkim.arc_verify(message)
        cv = arc_vrfy[0].decode("ascii")

    arc_res = authres.arc.ARCAuthenticationResult(result=cv)
    results_list += [arc_res]

except Exception as e:
    sys.stdout.write("X-MTA-Error: qmail-arc failed ARC verifying ({}).".format(e).encode("utf-8") + linesep)
    #raise
    pass

try:
    ### PREP AUTH RESULT
    auth_res = authres.AuthenticationResultsHeader(authserv_id=AUTHSERV_ID, results=results_list)
    auth_res_str = str(auth_res).encode("utf-8") + linesep

    message = auth_res_str + message

    # parameters: message, selector, domain, privkey, srv_id, signature_algorithm
    sig = dkim.arc_sign(message, DKIM_SELECTOR, DKIM_DOMAIN, privkey, b"eukelade.uberspace.de")
    #sys.stdout.write(repr(sig).encode("utf-8"))
    for line in sig:
        sys.stdout.write(line)
except Exception as e:
    sys.stdout.write("X-MTA-Error: qmail-arc failed ARC signing ({}).".format(e).encode("utf-8") + linesep)
    #raise
    pass

#sys.exit(0)
sys.stdout.write(message)
