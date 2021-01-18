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

This draft includes pseudocode that uses the functions and conventions defined
in {{!HPKE}}.

This draft uses the variable-length integer encoding from Section 16 of
{{!QUIC=I-D.ietf-quic-transport}}. Encoding and decoding variable-length
integers to a sequence of bytes are described using the functions `vencode()`
and `vdecode()`. The function `len()` takes the length of a sequence of bytes.

Formats are described using notation from Section 1.3 of {{!QUIC}}.


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

1. A binary-encoded HTTP message; see {{BINARY}}.
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

An Encapsulated Request is comprised of a length-prefixed key identifier and a
HPKE-protected request message. HPKE protection includes an encapsulated KEM
shared secret (or `enc`), plus the AEAD-protected request message. An
Encapsulated Request is shown in {{fig-enc-request}}. {{request}} describes the
process for constructing and processing an Encapsulated Request.

~~~
Key Identifer {
  Key ID Length (i),
  Key ID (..),
}

Encapsulated Request {
  Key Identifier (..),
  Encapsulated KEM Shared Secret (..),
  AEAD-Protected Request (..),
}
~~~
{: #fig-enc-request title="Encapsulated Request"}

Responses are bound to responses and so consist only of AEAD-protected content.
{{response}} describes the process for constructing and processing an
Encapsulated Response.

~~~
Encapsulated Response {
  Nonce (Nk),
  AEAD-Protected Response (..),
}
~~~
{: #fig-enc-response title="Encapsulated Response"}

The size of the Nonce field in an Encapsulated Response corresponds to the
size of an AEAD key for the corresponding HPKE ciphersuite.

## HPKE Encapsulation of Requests {#request}

Clients encapsulate a request `request` with an HPKE public key `pkR`,
whose wire-encoded Key Identifier is `keyID` as follows:

1. Compute an HPKE context using `pkR`, yielding `context` and encapsulation
   key `enc`.

2. Construct additional associated data, `aad`, by prepending a single byte
   with a value of 0x01 to the key identifier. The key identifier length is
   included in the AAD.

3. Encrypt (seal) `request` with `keyID` as associated data using `context`,
   yielding ciphertext `ct`.

4. Concatenate the length of `keyID` as a variable-length integer, `keyID`,
   `enc` and `ct`, yielding an Encapsulated Request `enc_request`. Note that 
   `enc` is of fixed-length, so there is no ambiguity in parsing `enc` and 
   `ct`.

In pseudocode, this procedure is as follows:

~~~
enc, context = SetupBaseS(pkR, "request")
ct = context.Seal(keyID, request)
enc_request = concat(keyID, enc, ct)
~~~

Servers decrypt an Encapsulated Request by reversing this process. Given an
Encapsulated Request `enc_request`, a server:

1. Parses `enc_request` into `keyID`, `enc`, and `ct` (indicated using the
   function `parse()` in pseudocode). The server is then able to find the HPKE
   private key, `skR`, corresponding to `keyID`. If no such key exists, the 
   server MUST return an error with HTTP status code 401.

2. Compute an HPKE context using `skR` and the encapsulated key `enc`, yielding
   `context`.

3. Construct additional associated data, `aad`, as the wire-encoded Key 
   Identifier `keyID` from `enc_request`.

4. Decrypt `ct` using `aad` as associated data, yielding `request` or an error
   on failure. If decryption fails, the server MUST return an error with HTTP 
   status code 400.

In pseudocode, this procedure is as follows:

~~~
keyID, enc, ct = parse(enc_request)
context = SetupBaseR(enc, skR, "request")
request, error = context.Open(keyID, ct)
~~~

Servers MUST verify that the request padding consists of all zeroes before
processing the corresponding Message.


## HPKE Encapsulation of Responses {#response}

Given an HPKE context `context`, a request message `request`, and a response
`response`, servers generate an Encapsulated Response `enc_response` as
follows:

1. Export a secret `secret` from `context`, using the string "response" as a
   label. The length of this secret is `Nk` - the length of an AEAD key
   assocated with `context`.

2. Extract a pseudorandom key `prk` using the `Extract` function provided by
   the KDF algorithm associated with `context`. The `ikm` input to this
   function is `secret`; the `salt` input is `request`.

3. Use the `Expand` function provided by the same KDF to extract an AEAD key
   `key`, of length `Nk` - the length of the keys used by the AEAD associated
   with `context`. Generating `key` uses a label of "key".

4. Use the same `Expand` function to extract a nonce `nonce` of length `Nn` -
   the length of the nonce used by the AEAD. Generating `nonce` uses a label of
   "nonce".

5. Encrypt `response`, passing the AEAD function Seal the values of `key`,
   `nonce`, `aad`, and a `pt` input of `request`, which yields `ct`.

6. Concatenate `response_nonce` and `ct`, yielding an Encapsulated Response
   `enc_response`. Note that `response_nonce` is of fixed-length, so there is no 
   ambiguity in parsing either `response_nonce` or `ct`.

In pseudocode, this procedure is as follows:

~~~
secret = context.Export("secret", Nk)
response_nonce = random(Nk)
salt = concat(enc, response_nonce)
prk = Extract(salt, secret)
aead_key = Expand(secret, "key", Nk)
aead_nonce = Expand(secret, "nonce", Nn)
enc_reponse = Seal(aead_key, aead_nonce, "", response)
~~~

Clients decrypt an Encapsulated Request by reversing this process. That is,
they first parse `enc_response` into `response_nonce` and `ct`. They then 
follow the same process to derive values for `aead_key` and `aead_nonce`.
Finally, the client decrypts `ct` using the Open function provided by the 
AEAD. Decrypting might produce an error, as shown.

~~~
reponse, error = Open(key, nonce, aad, enc_response)
~~~

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
