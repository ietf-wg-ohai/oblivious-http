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

  Dingledine2004:
    title: "Tor: The Second-Generation Onion Router"
    date: 2004-08
    target: "https://svn.torproject.org/svn/projects/design-paper/tor-design.html"
    author:
      - ins: R. Dingledine
      - ins: N. Mathewson
      - ins: P. Syverson


--- abstract

This document describes a system for the forwarding of encrypted HTTP messages.
This allows clients to make requests of servers without the server being able to
link requests to other requests from the same client.


--- middle

# Introduction

The act of making a request using HTTP reveals information about the client
identity to a server. Though the content of requests might reveal information,
that is information under the control of the client. In comparison, the source
address on the connection reveals information that a client has only limited
control over.

Even where an IP address is not directly attributed to an individual, the use
of an address over time can be used to correlate requests. Servers are able to
use this information to assemble profiles of client behavior, from which they
can make inferences about the people involved. The use of persistent
connections to make multiple requests improves performance, but provides
servers with additional certainty about the identity of clients in a similar
fashion.

Use of an HTTP proxy can provide a degree of protection against servers
correlating requests. Systems like virtual private networks or the Tor network
{{Dingledine2004}}, provide other options for clients.

Though the overhead imposed by these methods varies, the cost for each request
is significant. Preventing request linkability requires that each request
use a completely new TLS connection to the server. At a minimum,
this requires an additional round trip to the server in addition to that
required by the request. In addition to having high latency, there are
significant secondary costs, both in terms of the number of additional bytes
exchanged and the CPU cost of cryptographic computations.

This document describes a method of encapsulation for binary HTTP messages
{{BINARY}} using Hybrid Public Key Encryption (HPKE;
{{!HPKE=I-D.irtf-cfrg-hpke}}). This protects the content of both requests and
responses and enables a deployment architecture that can separate the identity
of a requester from the request.

Though this scheme requires that servers and proxies explicitly support it,
this design represents a performance improvement over options that perform just
one request in each connection. With limited trust placed in the proxy (see
{{trust}}), clients are assured that requests are not uniquely attributed to
them or linked to other requests.


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

## HPKE Encapsulation of Requests {#request}

Clients encapsulate a request `request` with an HPKE public key `pkR`,
whose Key Identifier is `keyID` as follows:

1. Compute an HPKE context using `pkR`, yielding `context` and encapsulation
   key `enc`.

2. Construct additional associated data, `aad`, by prepending a single byte
   with a value of 0x01 to the key identifier. The key identifier length is not
   included in the AAD.

3. Encrypt (seal) `request` with `keyID` as associated data using `context`,
   yielding ciphertext `ct`.

4. Concatenate the length of `keyID` as a variable-length integer, `keyID`,
   `enc` and `ct`, yielding an Encapsulated Request `enc_request`.

In pseudocode, this procedure is as follows:

~~~
enc, context = SetupBaseS(pkR, "request")
aad = concat(0x01, keyID)
ct = context.Seal(aad, request)
enc_request = concat(vencode(len(keyID)), keyID, enc, ct)
~~~

Servers decrypt an Encapsulated Request by reversing this process. Given an
Encapsulated Request `enc_request`, a server:

1. Parses `enc_request` into `keyID`, `enc`, and `ct` (indicated using the
   function `parse()` in pseudocode). The server is then able to find the HPKE
   private key, `skR`, corresponding to `keyID`.

2. Compute an HPKE context using `skR` and the encapsulated key `enc`, yielding
   `context`.

3. Construct additional associated data, `aad`, by prepending a single byte
   with a value of 0x01 to the key identifier.

4. Decrypt `ct` using `aad` as associated data, yielding `request` or an error
   on failure.

In pseudocode, this procedure is as follows:

~~~
keyID, enc, ct = parse(enc_request)
context = SetupBaseR(enc, skR, "request")
aad = concat(0x01, keyID)
request, error = context.Open(aad, ct)
~~~

Servers MUST verify that the request padding consists of all zeroes before
processing the corresponding Message.


## HPKE Encapsulation of Responses {#response}

Given an HPKE context `context`, a request message `request`, and a response
`response`, servers generate an Encapsulated Response `enc_response` as
follows:

1. Export a secret `secret` from `context`, using the string "response" as a
   label. The length of this secret is `Nsk` - the length of the secret
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

5. Construct additional associated data `aad`, that consists of a single byte
   with a value of 0x02. <!-- Do we really need anything here? If we drop this,
   we can drop the 0x01 prefix thing too. -->

6. Encrypt `response`, passing the AEAD function Seal the values of `key`,
   `nonce`, `aad`, and a `pt` input of `request`, which yields `enc_response`.

In pseudocode, this procedure is as follows:

~~~
secret = context.Export("secret", Nsk)
prk = Extract(request, secret)
key = Expand(secret, "key", Nk)
nonce = Expand(secret, "nonce", Nn)
aad = concat(0x02, emptyKeyID)
enc_reponse = Seal(key, nonce, aad, response)
~~~

Clients decrypt an Encapsulated Request by reversing this process. That is,
clients follow the same process to derive values for `key`, `nonce`, and `aad`.
The client then decrypts the Encapsulated Response using the Open function
provided by the AEAD. Decrypting might produce an error, as shown.

~~~
reponse, error = Open(key, nonce, aad, enc_response)
~~~


## Padding

Plaintext Messages support arbitrary length padding. Clients and servers MAY pad HTTP messages
as needed to hide metadata leakage through ciphertext length.


# Responsibility of Roles {#trust}

In this design, a client wishes to make a request of a server that is
authoritative for the oblivious target resource. The client wishes to make this
request without linking that request with either:

1. The identity at the network and transport layer of the client (that is, the
   client IP address and TCP or UDP port number the client uses to create a
   connection).

2. Any other request the client might have made in the past or might make in
   the future.

In order to ensure this, the client selects a proxy (that serves the oblivious
proxy resource) that it trusts will protect this information by forwarding the
encapsulated request and response without passing the server (that serves the
oblivious request resource).

In this section, a deployment where there are three entities is considered:

* A client makes requests and receives responses
* A proxy operates the oblivious proxy resource
* A server operates both the oblivious request resource and the oblivious
  target resource

To achieve the stated privacy goals, the oblivious proxy resource cannot be
operated by the same entity as the oblivious request resource. However,
colocation of the oblivious request resource and oblivious target resource
simplifies the interactions between those resources without affecting client
privacy.


## Client

Clients have the fewest direct responsibilities, though clients do need to
ensure that they do not undermine the process.

Clients cannot carry connection-level state between requests as they only
establish direct connections to the proxy responsible for the oblivious proxy
resource. However, clients need to ensure that they construct requests without
any information gained from previous requests. Otherwise, the server might be
able to use that information to link requests. Cookies {{?COOKIES=RFC6265}} are
the most obvious feature that MUST NOT be used by clients. However, clients
need to include all information learned from requests, which could include the
identity of resources.

Clients also need to ensure that they correctly generate a new HPKE context for
every request, using a good source of entropy ({{?RANDOM=RFC4086}}). Key reuse
not only risks linkability, but it could expose request and response contents
to the proxy. 

Clients constructing the request that is to be encapsulated need to avoid
including identifying information. Similarly, the request that is sent to the
oblivious request resource, though this request can contain only minimal
information as it only needs to include a method and the oblivious request
resource URL.


## Proxy Responsibilities

The proxy that serves the oblivious proxy resource has a very simple function
to perform. It forwards messages received at this resource to the oblivious
request resource, and forwards responses from the oblivious request resource
back to clients. The proxy MUST forward response status codes without
modification.

The proxy MUST NOT add information about the client identity when forwarding
requests. This includes the Via field, the Forwarded field
{{?FORWARDED=RFC7239}}, and any similar information.


### Denial of Service {#dos}

As there are privacy benefits from having a large rate of requests forwarded by
the same proxy (see {{ta}}), servers that operate the oblivious request
resource might need an arrangement with proxies. This arrangement might be
necessary to prevent having the large volume of requests being classified as an
attack by the server.

If a server does accept a large volume of requests from a proxy, it needs to
trust that the proxy does not allow abusive levels of request volumes from
clients. That is, if a server allows requests from the proxy to be exempt from
rate limits, the server might want to ensure that the proxy applies similar
rate limiting when receiving requests from clients.

Servers that enter into an agreement with a proxy that enables a higher request
rate might choose to authenticate the proxy to enable the higher rate.


### Linkability Through Traffic Analysis {#ta}

As the time at which encapsulated request or response messages are sent can
reveal information to a network observer. Though messages exchanged between the
oblivious proxy resource and the oblivious request resource might be sent in a
single connection, traffic analysis could be used to match messages that are
forwarded by the proxy.

A proxy could, as part of its function, add delays in order to increase the
anonymity set into which each message is attributed. This could latency to the
overall time clients take to receive a response, which might not what some
clients want.

A proxy can use padding to reduce the effectiveness of traffic analysis.

A proxy that forwards large volumes of exchanges can provide better privacy by
providing larger sets of messages that need to be matched.



## Server Responsibilities

A server that operates both oblivious request and oblivious target resources is
responsible for removing request encapsulation, generating a response the
encapsulated request, and encapsulating the response.

Servers should account for traffic analysis based on response size or generation time.
Techniques such as padding or timing delays can help protect against such attacks;
see {{ta}}.

If separate entities provide the oblivious request resource and oblivious
target resource, these entities might need an arrangement similar to that
between server and proxy for managing denial of service; see {{dos}}. It is
also necessary to provide confidentiality protection for the unprotected
requests and responses, plus protections for traffic analysis; see {{ta}}.


# Security Considerations

Words...


# IANA Considerations

TODO: Define a media type or types here.


--- back

# Acknowledgments
{: numbered="false"}

TODO: credit where credit is due.
