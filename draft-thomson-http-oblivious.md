---
title: "Oblivious HTTP"
docname: draft-thomson-http-oblivious-latest
category: std
ipr: trust200902
area: ART
workgroup: HTTPBIS

stand_alone: yes
pi: [toc, sortrefs, symrefs, docmapping]

author:
  -
    ins: M. Thomson
    name: Martin Thomson
    org: Mozilla
    email: mt@lowentropy.net

normative:

  BINARY:
    title: "Binary Representation of HTTP Messages"
    date: {DATE}
    seriesinfo:
      Internet-Draft: draft-ietf-http-binary-message-latest
    author:
      -
        ins: M.Thomson
        name: Martin Thomson
        org: Mozilla

informative:


--- abstract

This document describes a system for the forwarding of encrypted HTTP messages.
This allows clients to make requests of servers without the server being able to
link requests to other requests from the same client.


--- middle

# Introduction

Words...

This document describes a method of encapsulation for binary HTTP messages
{{BINARY}} using Hybrid Public Key Encryption (HPKE;
{{!HPKE=I-D.irtf-cfrg-hpke}}).

# Conventions and Definitions

{::boilerplate bcp14}

Encapsulated Request:

: An HTTP request that is encapsulated in an HPKE-encrypted message; see
  {{request}}.

Encapsulated Response:

: An HTTP response that is encapsulated in an HPKE-encrypted message; see
  {{response}}.

Oblivious Proxy Resource:

: An intermediary that forwards requests and responses between clients and a
  single oblivious request resource.

Oblivious Request Resource:

: A resource that can receive an encapsulated request, extract the contents of
  that request, forward it to an oblivious target resource, receive a response,
  encapsulate that response, then return that response.

Oblivious Target Resource:

: The resource that is the target of an encapsulated request.  This resource
  logically handles only regular HTTP requests and responses and so might be
  ignorant of the use of oblivious HTTP to reach it.


# Overview

A client learns the following:

* The identity of an oblivious request resource.  This might include some
  information about oblivious target resources that the oblivious request
  resource supports.

* The details of an HPKE public key that the oblivious request resource accepts,
  including an identifier for that key and the HPKE algorithms that are
  used with that key.

* The identity of an oblivious proxy resource that will forward encapsulated
  requests and responses to the oblivious request resource.

This information allows the client to make a request of an oblivious target
resource without that resource having only a limited ability to correlate that
request with the client IP or other requests that the client might make to that
server.

~~~
+---------+        +----------+        +----------+    +----------+
| Client  |        | Proxy    |        | Request  |    | Target   |
|         |        | Resource |        | Resource |    | Resource |
+---------+        +----------+        +----------+    +----------+
     |                  |                   |               |
     | Encapsulated     |                   |               |
     | Request          |                   |               |
     |----------------->| Encapsulated      |               |
     |                  | Request           |               |
     |                  |------------------>| Request       |
     |                  |                   |-------------->|
     |                  |                   |               |
     |                  |                   |      Response |
     |                  |      Encapsulated |<--------------|
     |                  |          Response |               |
     |     Encapsulated |<------------------|               |
     |         Response |                   |               |
     |<-----------------|                   |               |
     |                  |                   |               |
~~~
{: #fig-overview title="Overview of Oblivious HTTP"}

In order to make a request to an oblivious target resource, the following steps
occur, as shown in {{fig-overview}}:

1. The client constructs an HTTP request for an oblivious target resource.

2. The client encodes the HTTP request in a binary HTTP message and then
   encapsulates that message using HPKE and the process from {{request}}.

3. The client sends a POST request to the oblivious proxy resource with the
   encapsulated request as the content of that message.

4. The oblivious proxy resource forwards this request to the oblivious request
   resource.

5. The oblivious request resource receives this request and removes
   the HPKE protection to obtain an HTTP request.

6. The oblivious request resource makes an HTTP request that includes the target
   URI, method, fields, and content of the request it acquires.

7. The oblivious target resource answers this HTTP request with an HTTP
   response.

8. The oblivious request resource encapsulates the HTTP response following the
   process in {{response}} and sends this in response to the request from the
   oblivious proxy resource.

9. The oblivious proxy resource forwards this response to the client.

10. The client removes the encapsulation to obtain the response to the original
    request.


# HPKE Encapsulation

HTTP message encapsulation uses HPKE for request and response encryption.
An encapsulated HTTP message includes the following values:

1. A binary-encoded HTTP message [CITEME].
2. Padding of arbitrary length which MUST contain all zeroes.

The encoding of an HTTP message is as follows:

~~~
Plaintext Message {
  Message Length (i),
  Message (..),
  Padding Length (i),
  Padding (..),
}
~~~

This structure is then encrypted under a key with a specific identity, forming an encapsulated HTTP
message, with the following structure:

~~~
Key Identifer {
  Key ID Length (i),
  Key ID (..),
}

Encapsulated Message {
  Key Identifier (..)
  Encrypted Message Length (i),
  Encrypted Message (..),
}
~~~

The encapsulated message Key ID, as well as the encryption mechanics, are different for requests
and responses, as described below.

## HPKE Encapsulation of Requests {#request}

Clients encapsulate a request Plaintext Message `msg` with an HPKE public key `pkR`, whose Key Identifier
is `keyID` as follows:

1. Compute an HPKE context using `pkR`, yielding `context` and encapsulation key `enc`
2. Encrypt (seal) `msg` with `keyID` as associated data using `context`, yielding ciphertext `ct`
3. Concatenate `enc` and `ct`, yielding an Encrypted Message `encrypted_msg`

In pseudocode, this procedure is as follows:

~~~
enc, context = SetupBaseS(pkR, "request")
aad = 0x01 || keyID
encrypted_msg = context.Seal(aad, msg)
~~~

Clients construct the Encapsulated Message `req` using `keyID` and `encrypted_msg`.

Servers decrypt an Encapsulated Message by reversing this process. Given an Encapsulated Message `req` request
with Key Identifier `keyID` corresponding to an existing HPKE private key `skR`, servers decapsulate
the Message as follows:

1. Parse the `req` Encrypted Message as the concatenation of `enc` and `encrypted_message`
2. Compute an HPKE context using `skR` and the encapsulated key `enc` from `req`, yielding `context`
3. Decrypt `encrypted_message` with `keyID` as associated data, yielding `msg` or an error on failure

In pseudocode, this procedure is as follows:

~~~
context = SetupBaseR(enc, skR, "request")
aad = 0x01 || keyID
msg, error = context.Open(aad, ct)
~~~

Servers MUST verify that the Plaintext Message padding consists of all zeroes before processing the
corresponding Message.

## HPKE Encapsulation of Responses {#response}

Given an HPKE context `context` and a response Plaintext Message `resp` sent in response to a Plaintext
Message `req`, servers encrypt the data as follows:

1. Derive a symmetric key and nonce from `context`
2. Encrypt `resp` with empty Key Identifier `emptyKeyID` as associated data, yielding `encrypted_msg`

In pseudocode, this procedure is as follows:

~~~
secret = context.Export("secret", 32)
prk = Extract(req, secret)
key = Expand(secret, "key", Nk)
nonce = Expand(secret, "nonce", Nn)
aad = 0x02 || emptyKeyID
encrypted_msg = Seal(key, nonce, aad, resp)
~~~

Extract and Expand are functions corresponding to the HPKE context's KDF algorithm, and Seal, Nk, and
Nn correspond to the HPKE context's AEAD algorithm.

Clients decrypt an Encapsulated Message by reversing this process. Namely, they derive the
necessary AEAD parameters from an existing HPKE context and then decrypt (open) the Encapsulated
Message encrypted message.

## Padding

Plaintext Messages support arbitrary length padding. Clients and servers MAY pad HTTP messages
as needed to hide metadata leakage through ciphertext length.

# Responsibility of Roles

## Client

## Oblivious Proxy Resource

## Oblivious Request Resource

## Oblivious Target Resource


# Security Considerations

Words...


# IANA Considerations

TODO: Define a media type or types here.


--- back

# Acknowledgments
{: numbered="false"}

TODO: credit where credit is due.
