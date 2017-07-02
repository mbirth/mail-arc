#!/usr/bin/env python2
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
import dkim
import spf

AUTHSERV_ID = "uberspace.de"   # domain or hostname of mail server
DKIM_DOMAIN = "birth-online.de"
DKIM_SELECTOR = "mbirth"

# pylint: disable=C0103,C0301

if sys.version_info[0] >= 3:
    # Make sys.stdin and stdout binary streams.
    sys.stdin = sys.stdin.detach()
    sys.stdout = sys.stdout.detach()

privkey = open('.dkim-privkey', 'rb').read()

message = sys.stdin.read()

up_srv_ip_match = re.search(r"Received: from .* \(HELO (.*)\) \(([0-9a-f.:]+)\).*by ", message, re.MULTILINE | re.DOTALL)
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

# Find this line:
# Received: from unknown (HELO sv3-smtp2.lithium.com) (208.74.204.9)
#   by serpens.uberspace.de with SMTP; 23 Jun 2017 18:43:18 -0000

spf_result = spf.check2(i=up_srv_ip, s=sender_address, h=up_srv_helo)
spf_res = authres.SPFAuthenticationResult(result=spf_result[0], smtp_mailfrom=sender_address, smtp_helo=up_srv_helo, reason=spf_result[1])
results_list += [spf_res]

# Write Received-SPF header
sys.stdout.write('Received-SPF: {0} ({1}) client-ip={2} helo={3} envelope-from={4}'.format(spf_result[0], spf_result[1], up_srv_ip, up_srv_helo, sender_address)+"\n")


### ARC SIGNATURE

cv = dkim.CV_None
if re.search('arc-seal', message, re.IGNORECASE):
    arc_vrfy = dkim.arc_verify(message)
    cv = arc_vrfy[0]
    results_list += arc_vrfy[1]


### PREP AUTH RESULT
auth_res = authres.AuthenticationResultsHeader(authserv_id=AUTHSERV_ID, results=results_list)

sys.stdout.write(str(auth_res)+"\n")

# parameters: message, selector, domain, privkey, auth_results, chain_validation_status
sig = dkim.arc_sign(message, DKIM_SELECTOR, DKIM_DOMAIN, privkey, str(auth_res)[24:], cv)

for line in sig:
    sys.stdout.write(line)

sys.stdout.write(message)
