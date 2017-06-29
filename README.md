Qmail mail validator
====================

This is a script meant to be used in qmail before forwarding mail to e.g. Gmail. It will verify
incoming mail against SPF, DKIM and more and add the appropriate ARC headers. This makes Gmail
(hopefully) accept mails for which there's a DMARC rule with "reject" set.


What's the problem?
-------------------

To fight spam, people came up with things like [SPF], [DKIM] and [DMARC]. However, the one thing
they didn't think of was that mail can be forwarded. I, for example, have various forwards set up
on my web server, which forward mail sent to e.g. github.com@example.org to my Gmail account. This
way, should appear spam on an address, I know which site leaked my data, can block the address and
create a different one.

However, I recently noticed that mails from a specific sender don't get to my Gmail account anymore.

After some research, I found out they (the sender) set their DMARC policy to `p=reject` which means
that - should some validation check fail - the mail is to be rejected instead of moved to the Spam
folder. In this case, the SPF validation failed because of the forwarding to Gmail.


### SPF 101

[SPF] - the Sender Policy Framework - lets a domain owner define, which mail server(s) is/are
allowed to send mails for that domain. E.g. a record for `cmpny.com` could read:

    v=spf1 ip4:1.2.3.4 -all

This means, only the server 1.2.3.4 is allowed to deliver mails from `@cmpny.com`. This is totally
fine for 1:1 mail delivery. However, when forwarding, this becomes a problem. Let's assume this
chain:

```
     SEND                FWD               DEST
   ---------          ---------          ---------
  | 1.2.3.4 |  --->  | 2.3.4.5 |  --->  | 3.4.5.6 |
   ---------          ---------          ---------
  @cmpny.com         @example.org        @gmail.com
```

In this case, the `FWD` server might check the SPF and it checks out fine because 1.2.3.4 is the
allowed sending server for mails from `@cmpny.com`. However, when `DEST` validates against SPF, the
test will fail - because from `DEST`'s point of view, the mail got sent by `FWD` which isn't an
allowed sender for mails from `@cmpny.com`. This means, mails will get rejected if the policy is
set up strictly.

To circumvent this, people came up with [SRS]. SRS basically means: instead of forwarding the mail
as-is, we change the sender address to `@example.org`. This way, `DEST` will check against the SPF
record of `@example.org` and will find 2.3.4.5 as a valid sending server. Everything is fine.

Or is it?


### Interlude: Envelope-From and Header-From

Most people probably don't know that mails are sent in a virtual "envelope". You probably have
wondered once in a while, why mails addressed to `something@abc.de` ended up in your email inbox
although your email address is `else@xyz.com`. That is, because the `From:` and `To:` addresses you
see in your mail program are the addresses from the "letter" whereas the actual addresses used for
delivering the mail are on the "envelope".

An example: This is a simple communication between mail servers (answers from the server omitted):

```
HELO 1.2.3.4
MAIL FROM: <abc@cmpny.com>
RCPT TO: <xyz@example.org>
DATA
From: <something@abc.de>
To: <else@xyz.com>
Subject: Hahaha you'll never find me!

Hello user, buy this!
.
```

Your mail programm will show you `something@abc.de` as the sender and `else@xyz.com` as the
intended recipient. These addresses are from the mail *header* (i.e. the "letterhead"). However,
you can clearly see, that the mail server got a completely different information - namely:
`abc@cmpny.com` as the sender and `xyz@example.org` as the recipient. Those addresses are the
mail *envelope*.

Usually, addressees in the header and the envelope are identical.


### SRS and DMARC

Back to [SRS]. Applying SRS to a mail means changing the *envelope* sender address. In the example
above, the `FWD` server would replace the address `@cmpny.com` on the *envelope* by an address
`@example.org`. The `DEST` server will then check the SPF record of `example.org`, find the correct
server and the SPF check will pass.

But now comes DMARC. DMARC validation also includes checking whether the sender in the *header* is
the same as the sender on the *envelope*. As we've just changed one of the senders, this check
(called "alignment" check) will fail.

*"Well, then change the other sender, too!"* I hear you say. Well, that creates new problems.


### Changing both sender addresses

Suddenly, the mail program doesn't show `@cmpny.com` as the sender, but `@example.org`. So it can't
lookup the contact from your address book. You can't filter mails for everything from `@cmpny.com`.
And SRS also defines that the rewritten email addresses have changing parts, so mails sent from the
same sender `@cmpny.com` will have different sender addresses `@example.org` each and every time.
Good luck defining automatic sorting rules with that!

And then, there's DKIM.


### DKIM 101

[DKIM] is a way of validating a mail's integrity. This is done by calculating hashes/checksums over
mail headers and the body/text and adding those to the mail headers. The receiving server can then
verify these hashes to see if the mail has been changed since leaving the sender. The information
is encrypted using a private key only the sender knows. (The public key, needed for decryption, is
available via the sender's DKIM record.) This ensures that nobody can change the mail and generate
valid hashes for it.

Back to our example: So we've changed the `From:` address to `@example.org` so the DMARC validation
has "alignment" again and SPF validates fine. But now, the DKIM checksum doesn't match anymore,
because the `From:` header was changed. This makes the DMARC validation fail again and thus the
mail ends up being rejected again.


Solution: ARC
-------------

To fix these problems with forwarding mails, people came up with [ARC]. ARC means, the `FWD` server
will validate the mail and encrypt and embed the results in the mail's headers. `DEST` can then
decrypt the information from `FWD` and decide to trust it over its own SPF, DKIM and/or DMARC
results.

The ARC specification has been finalised in February 2017 and implemented by Gmail since then.


Usage
=====

This filter is meant to be used inline a `.qmail` file before forwarding. E.g.:

    mail-arc.py | forward you@example.org

To test it, you can throw a mail at it through normal piping:

    cat mymail.txt | SENDER=someone@cmpny.com ./mail-arc.py

The output is the mail with additional validation headers.


Notes
=====

Install dependencies using:

    pip install -r requirements.txt

If you get an error like:

> ipaddress.AddressValueError: '1.2.3.4' does not appear to be an IPv4 or IPv6 address. Did you
> pass in a bytes (str in Python 2) instead of a unicode object?

Uninstall the `ipaddress` module (so the script uses `ipaddr`):

    pip uninstall ipaddress

* [ARC]: Authenticated Received Chain
* [DKIM]: DomainKeys Identified Mail
* [DMARC]: Domain-based Message Authentication, Reporting and Conformance
* [SPF]: Sender Policy Framework
* [SRS]: Sender Rewriting Scheme


[ARC]: https://en.wikipedia.org/wiki/Authenticated_Received_Chain
[DKIM]: https://en.wikipedia.org/wiki/DomainKeys_Identified_Mail
[DMARC]: https://en.wikipedia.org/wiki/DMARC
[SPF]: https://en.wikipedia.org/wiki/Sender_Policy_Framework
[SRS]: https://en.wikipedia.org/wiki/Sender_Rewriting_Scheme
