---
title: "Oblivious HTTP"
docname: draft-ietf-ohai-ohttp-latest
category: std
ipr: trust200902
area: "Security"
workgroup: "Oblivious HTTP Application Intermediation"
venue:
  group: "Oblivious HTTP Application Intermediation"
  type: "Working Group"
  mail: "ohai@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/ohai/"
  github: "ietf-wg-ohai/oblivious-http"
  latest: "https://ietf-wg-ohai.github.io/oblivious-http/draft-ietf-ohai-ohttp.html"

stand_alone: yes
pi: [toc, sortrefs, symrefs, docmapping]

author:
  -
    ins: M. Thomson
    name: Martin Thomson
    org: Mozilla
    email: mt@lowentropy.net
  -
    ins: C.A. Wood
    name: Christopher A. Wood
    org: Cloudflare
    email: caw@heapingbits.net

normative:

  BINARY: I-D.ietf-httpbis-binary-message
  HTTP: RFC9110
  QUIC: RFC9000
  TLS: RFC8446

informative:

  Dingledine2004:
    title: "Tor: The Second-Generation Onion Router"
    date: 2004-08
    target: "https://svn.torproject.org/svn/projects/design-paper/tor-design.html"
    author:
      - ins: R. Dingledine
      - ins: N. Mathewson
      - ins: P. Syverson

  PRIO:
    title: "Prio: Private, Robust, and Scalable Computation of Aggregate Statistics"
    date: 2017-03-14
    target: "https://crypto.stanford.edu/prio/paper.pdf"
    author:
      - ins: H. Corrigan-Gibbs
      - ins: D. Boneh

  ODoH:
    title: "Oblivious DNS over HTTPS (ODoH): A Practical Privacy Enhancement to DNS"
    date: 2021-01-07
    target: https://www.petsymposium.org/2021/files/papers/issue4/popets-2021-0085.pdf
    author:
      - fullname: Sudheesh Singanamalla
      - fullname: Suphanat Chunhapanya
      - fullname: Marek Vavrusa
      - fullname: Tanya Verma
      - fullname: Peter Wu
      - fullname: Marwan Fayed
      - fullname: Kurtis Heimerl
      - fullname: Nick Sullivan
      - fullname: Christopher A. Wood

  OHTTP-ANALYSIS:
    title: "Tamarin Model of Oblivious HTTP"
    date: 2021-08-23
    target: https://github.com/cloudflare/ohttp-analysis
    author:
      - fullname: Jonathan Hoyland

  UWT:
    title: "Unsanctioned Web Tracking"
    author:
      fullname: Mark Nottingham
    date: 2015-07-17
    target: https://www.w3.org/2001/tag/doc/unsanctioned-tracking/


--- abstract

This document describes a system for the forwarding of encrypted HTTP messages.
This allows a client to make multiple requests of a server without the server being able
to link those requests to the client or to identify the requests as having come
from the same client.


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
{{BINARY}} using Hybrid Public Key Encryption (HPKE; {{!HPKE=RFC9180}}). This
protects the content of both requests and responses and enables a deployment
architecture that can separate the identity of a requester from the request.

Though this scheme requires that servers and proxies (called relays in this document)
explicitly support it, this design represents a performance improvement over options
that perform just one request in each connection. With limited trust placed in the
relay (see {{security}}), clients are assured that requests are not uniquely
attributed to them or linked to other requests.


# Overview

A client must initially know the following:

* The identity of an Oblivious Gateway Resource.  This might include some
  information about what Target Resources the Oblivious Gateway Resource
  supports.

* The details of an HPKE public key that the Oblivious Gateway Resource
  accepts, including an identifier for that key and the HPKE algorithms that
  are used with that key.

* The identity of an Oblivious Relay Resource that will accept relay requests
  carrying an encapsulated request as its content and forward the content in
  these requests to a single Oblivious Gateway Resource. See {{proxy-state}}
  for more information about the mapping between Oblivious Relay and Gateway
  Resources.

This information allows the client to make a request of a Target Resource with
that resource having only a limited ability to correlate that request with the
client IP or other requests that the client might make to that server.

~~~ aasvg
+---------+       +----------+      +----------+      +----------+
| Client  |       | Relay    |      | Gateway  |      | Target   |
|         |       | Resource |      | Resource |      | Resource |
+----+----+       +----+-----+      +-------+--+      +----+-----+
     |                 |                    |              |
     | Relay           |                    |              |
     | Request         |                    |              |
     | [+ Encapsulated |                    |              |
     |    Request ]    |                    |              |
     +---------------->| Gateway            |              |
     |                 | Request            |              |
     |                 | [+ Encapsulated    |              |
     |                 |    Request ]       |              |
     |                 +------------------->| Request      |
     |                 |                    +------------->|
     |                 |                    |              |
     |                 |                    |     Response |
     |                 |            Gateway |<-------------+
     |                 |           Response |              |
     |                 |    [+ Encapsulated |              |
     |                 |         Response ] |              |
     |           Relay |<-------------------+              |
     |        Response |                    |              |
     | [+ Encapsulated |                    |              |
     |      Response ] |                    |              |
     |<----------------+                    |              |
     |                 |                    |              |
~~~
{: #fig-overview title="Overview of Oblivious HTTP"}

In order to make a request to a Target Resource, the following steps occur, as
shown in {{fig-overview}}:

1. The client constructs an HTTP request for a Target Resource.

2. The client encodes the HTTP request in a binary HTTP message and then
   encapsulates that message using HPKE and the process from {{request}}.

3. The client sends a POST request to the Oblivious Relay Resource with the
   Encapsulated Request as the content of that message.

4. The Oblivious Relay Resource forwards this request to the Oblivious Gateway
   resource.

5. The Oblivious Gateway Resource receives this request and removes
   the HPKE protection to obtain an HTTP request.

6. The Oblivious Gateway Resource makes an HTTP request that includes the target
   URI, method, fields, and content of the request it acquires.

7. The Target Resource answers this HTTP request with an HTTP response.

8. The Oblivious Gateway Resource encapsulates the HTTP response following the
   process in {{response}} and sends this in response to the request from the
   Oblivious Relay Resource.

9. The Oblivious Relay Resource forwards this response to the client.

10. The client removes the encapsulation to obtain the response to the original
    request.


## Applicability

Oblivious HTTP has limited applicability.  Many uses of HTTP benefit
from being able to carry state between requests, such as with cookies
({{?RFC6265}}), authentication ({{Section 11 of HTTP}}), or even
alternative services ({{?RFC7838}}).  Oblivious HTTP removes linkage
at the transport layer, which must be used in conjunction with applications
that do not carry state between requests.

Oblivious HTTP is primarily useful where privacy risks associated with possible
stateful treatment of requests are sufficiently large that the cost of
deploying this protocol can be justified.  Oblivious HTTP is simpler and less
costly than more robust systems, like Prio ({{PRIO}}) or Tor
({{Dingledine2004}}), which can provide stronger guarantees at higher
operational costs.

Oblivious HTTP is more costly than a direct connection to a server.  Some costs,
like those involved with connection setup, can be amortized, but there are
several ways in which Oblivious HTTP is more expensive than a direct request:

* Each request requires at least two regular HTTP requests, which adds latency.

* Each request is expanded in size with additional HTTP fields,
  encryption-related metadata, and AEAD expansion.

* Deriving cryptographic keys and applying them for request and
  response protection takes non-negligible computational resources.

Examples of where preventing the linking of requests might justify these costs
include:

* DNS queries.  DNS queries made to a recursive resolver reveal information
  about the requester, particularly if linked to other queries.

* Telemetry submission.  Applications that submit reports about their usage to
  their developers might use Oblivious HTTP for some types of moderately
  sensitive data.

These are examples of requests where there is information in a request that - if
it were connected to the identity of the user - might allow a server to learn
something about that user even if the identity of the user is pseudonymous.
Other examples include the submission of anonymous surveys, making search
queries, or requesting location-specific content (such as retrieving tiles of a
map display).


## Conventions and Definitions

{::boilerplate bcp14-tagged}

Client:

: This document uses its own definition of client.  When referring to the HTTP
  definition of client ({{Section 3.3 of HTTP}}), the term "HTTP client" is
  used; see {{http-usage}}.

Encapsulated Request:

: An HTTP request that is encapsulated in an HPKE-encrypted message; see
  {{request}}.

Encapsulated Response:

: An HTTP response that is encapsulated in an HPKE-encrypted message; see
  {{response}}.

Oblivious Relay Resource:

: An intermediary that forwards encapsulated requests and responses between
  clients and a single Oblivious Gateway Resource.

Oblivious Gateway Resource:

: A resource that can receive an encapsulated request, extract the contents of
  that request, forward it to a Target Resource, receive a response,
  encapsulate that response, then return that response.

Target Resource:

: The resource that is the target of an encapsulated request.  This resource
  logically handles only regular HTTP requests and responses and so might be
  ignorant of the use of Oblivious HTTP to reach it.

Relay Request:

: An HTTP request from Client to Relay that contains an encapsulated request as the content.

Relay Response:

: An HTTP response from Relay to Client that contains an encapsulated response as the content.

Gateway Request:

: An HTTP request from Relay to Gateway that contains an encapsulated request as the content.

Gateway Response:

: An HTTP response from Gateway to Relay that contains an encapsulated response as the content.

This draft includes pseudocode that uses the functions and conventions defined
in {{!HPKE}}.

Encoding an integer to a sequence of bytes in network byte order is described
using the function `encode(n, v)`, where `n` is the number of bytes and `v` is
the integer value.  ASCII {{!ASCII=RFC0020}} encoding of a string `s` is
indicated using the function `encode_str(s)`.  The function `len()` returns the
length of a sequence of bytes.

Formats are described using notation from {{Section 1.3 of QUIC}}.


# Key Configuration {#key-configuration}

A client needs to acquire information about the key configuration of the
Oblivious Gateway Resource in order to send encapsulated requests.
In order to ensure that clients do not encapsulate messages that other entities
can intercept, the key configuration MUST be authenticated and have integrity
protection.

This document does not define how that acquisition occurs. However, in
order to help facilitate interoperability, it does specify a format
for the keys. This ensures that different
client implementations can be configured in the same way and also
enables advertising key configurations in a consistent format.  This
format might be used, for example with HTTPS, as part of a system for
configuring or discovering key configurations.  Note however that such
a system needs to consider the potential for key configuration to be
used to compromise client privacy; see {{privacy}}.

A client might have multiple key configurations to select from when
encapsulating a request. Clients are responsible for selecting a preferred key
configuration from those it supports. Clients need to consider both the key
encapsulation method (KEM) and the combinations of key derivation function
(KDF) and authenticated encryption with associated data (AEAD) in this
decision.

## Key Configuration Encoding {#key-config}

A single key configuration consists of a key identifier, a public key, an
identifier for the KEM that the public key uses, and a set HPKE symmetric
algorithms. Each symmetric algorithm consists of an identifier for a KDF and an
identifier for an AEAD.

{{format-key-config}} shows a single key configuration.

~~~ tls-syntax
HPKE Symmetric Algorithms {
  HPKE KDF ID (16),
  HPKE AEAD ID (16),
}

OHTTP Key Config {
  Key Identifier (8),
  HPKE KEM ID (16),
  HPKE Public Key (Npk * 8),
  HPKE Symmetric Algorithms Length (16),
  HPKE Symmetric Algorithms (32..262140),
}
~~~
{: #format-key-config title="A Single Key Configuration"}

The definitions for the identifiers used in HPKE and the semantics of the
algorithms they identify can be found in {{!HPKE}}.  The `Npk` parameter is
determined by the choice of HPKE KEM, which can also be found in {{!HPKE}}.


## Key Configuration Media Type {#ohttp-keys}

The "application/ohttp-keys" format is a media type that identifies a
serialized collection of key configurations. The content of this media
type comprises one or more key configuration encodings (see
{{key-config}}) that are concatenated.

Evolution of the key
configuration format is supported through the definition of new
formats that are identified by new media types.

Type name:

: application

Subtype name:

: ohttp-keys

Required parameters:

: N/A

Optional parameters:

: None

Encoding considerations:

: only "8bit" or "binary" is permitted

Security considerations:

: see {{security}}

Interoperability considerations:

: N/A

Published specification:

: this specification

Applications that use this media type:

: N/A

Fragment identifier considerations:

: N/A

Additional information:

: <dl>
  <dt>Magic number(s):</dt><dd>N/A</dd>
  <dt>Deprecated alias names for this type:</dt><dd>N/A</dd>
  <dt>File extension(s):</dt><dd>N/A</dd>
  <dt>Macintosh file type code(s):</dt><dd>N/A</dd>
  </dl>

Person and email address to contact for further information:

: see Authors' Addresses section

Intended usage:

: COMMON

Restrictions on usage:

: N/A

Author:

: see Authors' Addresses section

Change controller:

: IESG


# HPKE Encapsulation

HTTP message encapsulation uses HPKE for request and response encryption.

An encapsulated HTTP request contains a binary-encoded HTTP message {{BINARY}}
and no other fields; see {{fig-req-pt}}.

~~~
Request {
  Binary HTTP Message (..),
}
~~~
{: #fig-req-pt title="Plaintext Request Content"}

An Encapsulated Request is comprised of a key identifier and a HPKE-protected
request message. HPKE protection includes an encapsulated KEM shared secret (or
`enc`), plus the AEAD-protected request message. An Encapsulated Request is
shown in {{fig-enc-request}}. {{request}} describes the process for constructing
and processing an Encapsulated Request.

~~~
Encapsulated Request {
  Key Identifier (8),
  KEM Identifier (16),
  KDF Identifier (16),
  AEAD Identifier (16),
  Encapsulated KEM Shared Secret (8*Nenc),
  AEAD-Protected Request (..),
}
~~~
{: #fig-enc-request title="Encapsulated Request"}

The Nenc parameter corresponding to the HpkeKdfId can be found in {{Section 7.1
of !HPKE}}.

An encrypted HTTP response includes a binary-encoded HTTP message {{BINARY}}
and no other content; see {{fig-res-pt}}.

~~~
Response {
  Binary HTTP Message (..),
}
~~~
{: #fig-res-pt title="Plaintext Response Content"}

Responses are bound to requests and so consist only of AEAD-protected content.
{{response}} describes the process for constructing and processing an
Encapsulated Response.

~~~
Encapsulated Response {
  Nonce (Nk),
  AEAD-Protected Response (..),
}
~~~
{: #fig-enc-response title="Encapsulated Response"}


The Nenc and Nk parameters corresponding to the HpkeKdfId can be found in
{{!HPKE}}.  Nenc refers to the size of the encapsulated KEM shared secret, in
bytes; Nk refers to the size of the AEAD key for the HPKE ciphersuite, in bits.


## Encapsulation of Requests {#request}

Clients encapsulate a request `request` using values from a key configuration:

* the key identifier from the configuration, `keyID`, with the corresponding KEM
  identified by `kemID`,

* the public key from the configuration, `pkR`, and

* a selected combination of KDF, identified by `kdfID`, and AEAD, identified by
  `aeadID`.

The client then constructs an Encapsulated Request, `enc_request`, from a binary
encoded HTTP request, `request`, as follows:

1. Construct a message header, `hdr`, by concatenating the values of `keyID`,
   `kemID`, `kdfID`, and `aeadID`, as one 8-bit integer and three 16-bit
   integers, respectively, each in network byte order.

2. Build `info` by concatenating the ASCII-encoded string "message/bhttp
   request", a zero byte, and the header.

3. Create a sending HPKE context by invoking `SetupBaseS()` ({{Section 5.1.1 of
   HPKE}}) with the public key of the receiver `pkR` and `info`.  This yields
   the context `sctxt` and an encapsulation key `enc`.

4. Encrypt `request` by invoking the `Seal()` method on `sctxt` ({{Section 5.2
   of HPKE}}) with empty associated data `aad`, yielding ciphertext `ct`.

5. Concatenate the values of `hdr`, `enc`, and `ct`, yielding an Encrypted
   Request `enc_request`.

Note that `enc` is of fixed-length, so there is no ambiguity in parsing this
structure.

In pseudocode, this procedure is as follows:

~~~
hdr = concat(encode(1, keyID),
             encode(2, kemID),
             encode(2, kdfID),
             encode(2, aeadID))
info = concat(encode_str("message/bhttp request"),
              encode(1, 0),
              hdr)
enc, sctxt = SetupBaseS(pkR, hdr)
ct = sctxt.Seal([], request)
enc_request = concat(hdr, enc, ct)
~~~

Servers decrypt an Encapsulated Request by reversing this process. Given an
Encapsulated Request `enc_request`, a server:

1. Parses `enc_request` into `keyID`, `kemID`, `kdfID`, `aeadID`, `enc`, and
   `ct` (indicated using the function `parse()` in pseudocode). The server is
   then able to find the HPKE private key, `skR`, corresponding to `keyID`.

   a. If `keyID` does not identify a key matching the type of `kemID`, the
      server returns an error.

   b. If `kdfID` and `aeadID` identify a combination of KDF and AEAD that the
      server is unwilling to use with `skR`, the server returns an error.

2. Build `info` by concatenating the ASCII-encoded string "message/bhttp
   request", a zero byte, `keyID` as an 8-bit integer, plus `kemID`, `kdfID`,
   and `aeadID` as three 16-bit integers.

3. Create a receiving HPKE context by invoking `SetupBaseR()` ({{Section 5.1.1
   of HPKE}}) with `skR`, `enc`, and `info`.  This produces a context `rctxt`.

4. Decrypt `ct` by invoking the `Open()` method on `rctxt` ({{Section 5.2 of
   HPKE}}), with an empty associated data `aad`, yielding `request` or an error
   on failure. If decryption fails, the server returns an error.

In pseudocode, this procedure is as follows:

~~~
keyID, kemID, kdfID, aeadID, enc, ct = parse(enc_request)
info = concat(encode_str("message/bhttp request"),
              encode(1, 0),
              encode(1, keyID),
              encode(2, kemID),
              encode(2, kdfID),
              encode(2, aeadID))
rctxt = SetupBaseR(enc, skR, info)
request, error = rctxt.Open([], ct)
~~~


## Encapsulation of Responses {#response}

Given an HPKE context `context`, a request message `request`, and a response
`response`, servers generate an Encapsulated Response `enc_response` as
follows:

1. Export a secret `secret` from `context`, using the string "message/bhttp
   response" as context.  The length of this secret is `max(Nn, Nk)`, where `Nn`
   and `Nk` are the length of AEAD key and nonce associated with `context`.

2. Generate a random value of length `max(Nn, Nk)` bytes, called
   `response_nonce`.

3. Extract a pseudorandom key `prk` using the `Extract` function provided by
   the KDF algorithm associated with `context`. The `ikm` input to this
   function is `secret`; the `salt` input is the concatenation of `enc` (from
   `enc_request`) and `response_nonce`

4. Use the `Expand` function provided by the same KDF to extract an AEAD key
   `key`, of length `Nk` - the length of the keys used by the AEAD associated
   with `context`. Generating `key` uses a label of "key".

5. Use the same `Expand` function to extract a nonce `nonce` of length `Nn` -
   the length of the nonce used by the AEAD. Generating `nonce` uses a label of
   "nonce".

6. Encrypt `response`, passing the AEAD function Seal the values of `key`,
   `nonce`, empty `aad`, and a `pt` input of `request`, which yields `ct`.

7. Concatenate `response_nonce` and `ct`, yielding an Encapsulated Response
   `enc_response`. Note that `response_nonce` is of fixed-length, so there is no
   ambiguity in parsing either `response_nonce` or `ct`.

In pseudocode, this procedure is as follows:

~~~
secret = context.Export("message/bhttp response", Nk)
response_nonce = random(max(Nn, Nk))
salt = concat(enc, response_nonce)
prk = Extract(salt, secret)
aead_key = Expand(prk, "key", Nk)
aead_nonce = Expand(prk, "nonce", Nn)
ct = Seal(aead_key, aead_nonce, "", response)
enc_response = concat(response_nonce, ct)
~~~

Clients decrypt an Encapsulated Response by reversing this process. That is,
they first parse `enc_response` into `response_nonce` and `ct`. They then
follow the same process to derive values for `aead_key` and `aead_nonce`.

The client uses these values to decrypt `ct` using the Open function provided by
the AEAD. Decrypting might produce an error, as follows:

~~~
reponse, error = Open(aead_key, aead_nonce, "", ct)
~~~


# HTTP Usage {#http-usage}

A client interacts with the Oblivious Relay Resource by constructing an
Encapsulated Request.  This Encapsulated Request is included as the content of a
POST request to the Oblivious Relay Resource.  This request MUST only contain
those fields necessary to carry the Encapsulated Request: a method of POST, a
target URI of the Oblivious Relay Resource, a header field containing
the content type (see ({{media-types}}), and the Encapsulated Request as the
request content. In the request to the Oblivious Relay Resource, clients MAY
include additional fields. However, those fields MUST be independent of the
Encapsulated Request and MUST be fields that the Oblivious Relay Resource will
remove before forwarding the Encapsulated Request towards the target, such as the
Connection or Proxy-Authorization header fields {{?SEMANTICS=RFC9110}}.

The client role in this protocol acts as an HTTP client both with respect to the
Oblivious Relay Resource and the Target Resource.  For the request the clients
makes to the Target Resource, this diverges from typical HTTP assumptions about
the use of a connection (see {{Section 3.3 of HTTP}}) in that the request and
response are encrypted rather than sent over a connection.  The Oblivious Relay
Resource and the Oblivious Gateway Resource also act as HTTP clients toward the
Oblivious Gateway Resource and Target Resource respectively.

The Oblivious Relay Resource interacts with the Oblivious Gateway Resource as an
HTTP client by constructing a request using the same restrictions as the client
request, except that the target URI is the Oblivious Gateway Resource.  The
content of this request is copied from the client.  The Oblivious Relay Resource
MUST NOT add information to the request without the client being aware of
the type of information that might be added; see
{{relay-responsibilities}} for more information on relay responsibilities.

When a response is received from the Oblivious Gateway Resource, the
Oblivious Relay Resource forwards the response according to the rules of an
HTTP proxy; see {{Section 7.6 of HTTP}}.

An Oblivious Gateway Resource, if it receives any response from the Target
Resource, sends a single 200 response containing the encapsulated response.
Like the request from the client, this response MUST only contain those fields
necessary to carry the encapsulated response: a 200 status code, a header field
indicating the content type, and the encapsulated response as the response
content.  As with requests, additional fields MAY be used to convey information
that does not reveal information about the encapsulated response.

An Oblivious Gateway Resource acts as a gateway for requests to the Target
Resource (see {{Section 7.6 of HTTP}}).  The one exception is that any
information it might forward in a response MUST be encapsulated, unless it is
responding to errors it detects before removing encapsulation of the request;
see {{errors}}.


## Informational Responses

This encapsulation does not permit progressive processing of responses.  Though
the binary HTTP response format does support the inclusion of informational
(1xx) status codes, the AEAD encapsulation cannot be removed until the entire
message is received.

In particular, the Expect header field with 100-continue (see {{Section 10.1.1 of
HTTP}}) cannot be used.  Clients MUST NOT
construct a request that includes a 100-continue expectation; the Oblivious
Gateway Resource MUST generate an error if a 100-continue expectation is
received.


## Errors

A server that receives an invalid message for any reason MUST generate an HTTP
response with a 4xx status code.

Errors detected by the Oblivious Relay Resource and errors detected by the
Oblivious Gateway Resource before removing protection (including being unable to
remove encapsulation for any reason) result in the status code being sent
without protection in response to the POST request made to that resource.

Errors detected by the Oblivious Gateway Resource after successfully removing
encapsulation and errors detected by the Target Resource MUST be sent in an
Encapsulated Response.


# Media Types {#media-types}

Media types are used to identify Encapsulated Requests and Responses.

Evolution of the format of Encapsulated Requests and Responses is supported
through the definition of new formats that are identified by new media types.


## message/ohttp-req Media Type

The "message/ohttp-req" identifies an encrypted binary HTTP request.  This
is a binary format that is defined in {{request}}.

Type name:

: message

Subtype name:

: ohttp-req

Required parameters:

: N/A

Optional parameters:

: None

Encoding considerations:

: only "8bit" or "binary" is permitted

Security considerations:

: see {{security}}

Interoperability considerations:

: N/A

Published specification:

: this specification

Applications that use this media type:

: N/A

Fragment identifier considerations:

: N/A

Additional information:

: <dl>
  <dt>Magic number(s):</dt><dd>N/A</dd>
  <dt>Deprecated alias names for this type:</dt><dd>N/A</dd>
  <dt>File extension(s):</dt><dd>N/A</dd>
  <dt>Macintosh file type code(s):</dt><dd>N/A</dd>
  </dl>

Person and email address to contact for further information:

: see Authors' Addresses section

Intended usage:

: COMMON

Restrictions on usage:

: N/A

Author:

: see Authors' Addresses section

Change controller:

: IESG


## message/ohttp-res Media Type

The "message/ohttp-res" identifies an encrypted binary HTTP response. This
is a binary format that is defined in {{response}}.

Type name:

: message

Subtype name:

: ohttp-res

Required parameters:

: N/A

Optional parameters:

: None

Encoding considerations:

: only "8bit" or "binary" is permitted

Security considerations:

: see {{security}}

Interoperability considerations:

: N/A

Published specification:

: this specification

Applications that use this media type:

: N/A

Fragment identifier considerations:

: N/A

Additional information:

: <dl>
  <dt>Magic number(s):</dt><dd>N/A</dd>
  <dt>Deprecated alias names for this type:</dt><dd>N/A</dd>
  <dt>File extension(s):</dt><dd>N/A</dd>
  <dt>Macintosh file type code(s):</dt><dd>N/A</dd>
  </dl>

Person and email address to contact for further information:

: see Authors' Addresses section

Intended usage:

: COMMON

Restrictions on usage:

: N/A

Author:

: see Authors' Addresses section

Change controller:

: IESG


# Security Considerations {#security}

In this design, a client wishes to make a request of a server that is
authoritative for the Target Resource. The client wishes to make this request
without linking that request with either:

1. The identity at the network and transport layer of the client (that is, the
   client IP address and TCP or UDP port number the client uses to create a
   connection).

2. Any other request the client might have made in the past or might make in
   the future.

In order to ensure this, the client selects a relay (that serves the
Oblivious Relay Resource) that it trusts will protect this information
by forwarding the Encapsulated Request and Response without passing it
to the server (that serves the Oblivious Gateway Resource).

In this section, a deployment where there are three entities is considered:

* A client makes requests and receives responses
* A relay operates the Oblivious Relay Resource
* A server operates both the Oblivious Gateway Resource and the Target Resource

To achieve the stated privacy goals, the Oblivious Relay Resource cannot be
operated by the same entity as the Oblivious Gateway Resource. However,
colocation of the Oblivious Gateway Resource and Target Resource simplifies the
interactions between those resources without affecting client privacy.

As a consequence of this configuration, Oblivious HTTP prevents linkability
described above. Informally, this means:

1. Requests and responses are known only to clients and targets in possession
   of the corresponding response encapsulation key and HPKE keying material.
   In particular, the Oblivious Relay knows the origin and destination of an
   Encapsulated Request and Response, yet does not know the decrypted
   contents. Likewise, targets know only the Oblivious Gateway origin, i.e.,
   the relay, and the decrypted request. Only the client knows both the
   plaintext request and response.
1. Targets cannot link requests from the same client in the absence of unique
   per-client keys.

Traffic analysis that might affect these properties are outside the scope of
this document; see {{ta}}.

A formal analysis of Oblivious HTTP is in {{OHTTP-ANALYSIS}}.


## Client Responsibilities

Clients MUST ensure that the key configuration they select for generating
Encapsulated Requests is integrity protected and authenticated so that it can
be attributed to the Oblivious Gateway Resource; see {{key-configuration}}.

Since clients connect directly to the relay instead of the target, application
configurations wherein clients make policy decisions about target connections,
e.g., to apply certificate pinning, are incompatible with Oblivious HTTP.  In
such cases, alternative technologies such as HTTP CONNECT
({{Section 9.3.6 of HTTP}}) can be used. Applications could implement related
policies on key configurations and relay connections, though these might not
provide the same properties as policies enforced directly on target
connections. When this difference is relevant, applications can instead connect
directly to the target at the cost of either privacy or performance.

Clients MUST NOT include identifying information in the request that is
encrypted. Identifying information includes cookies {{?COOKIES=RFC6265}},
authentication credentials or tokens, and any information that might reveal
client-specific information such as account credentials.

Clients cannot carry connection-level state between requests as they only
establish direct connections to the relay responsible for the Oblivious Relay
resource. However, clients need to ensure that they construct requests without
any information gained from previous requests. Otherwise, the server might be
able to use that information to link requests. Cookies {{?COOKIES=RFC6265}} are
the most obvious feature that MUST NOT be used by clients. However, clients
need to include all information learned from requests, which could include the
identity of resources.

Clients MUST generate a new HPKE context for every request, using a good source
of entropy ({{?RANDOM=RFC4086}}) for generating keys. Key reuse not only risks
requests being linked, reuse could expose request and response contents to the
relay.

The request the client sends to the Oblivious Relay Resource only requires
minimal information; see {{http-usage}}. The request that carries the
Encapsulated Request and is sent to the Oblivious Relay Resource MUST NOT
include identifying information unless the client ensures that this information
is removed by the relay. A client MAY include information only for the
Oblivious Relay Resource in header fields identified by the Connection header
field if it trusts the relay to remove these as required by Section 7.6.1 of
{{HTTP}}. The client needs to trust that the relay does not replicate the
source addressing information in the request it forwards.

Clients rely on the Oblivious Relay Resource to forward Encapsulated Requests
and responses. However, the relay can only refuse to forward messages, it
cannot inspect or modify the contents of Encapsulated Requests or responses.


## Relay Responsibilities

The relay that serves the Oblivious Relay Resource has a very simple function
to perform. For each request it receives, it makes a request of the Oblivious
Gateway Resource that includes the same content. When it receives a response,
it sends a response to the client that includes the content of the response
from the Oblivious Gateway Resource.

When forwarding a request, the relay MUST follow the forwarding rules in
{{Section 7.6 of HTTP}}.  A generic HTTP intermediary implementation is suitable
for the purposes of serving an Oblivious Relay Resource, but additional care is
needed to ensure that client privacy is maintained.

Firstly, a generic implementation will forward unknown fields.  For Oblivious
HTTP, a Oblivious Relay Resource SHOULD NOT forward unknown fields.  Though
clients are not expected to include fields that might contain identifying
information, removing unknown fields removes this privacy risk.

Secondly, generic implementations are often configured to augment requests with
information about the client, such as the Via field or the Forwarded field
{{?FORWARDED=RFC7239}}.  A relay MUST NOT add information when forwarding
requests that might be used to identify clients, with the exception of
information that a client is aware of.

Finally, a relay can also generate responses, though it assumed to not be able
to examine the content of a request (other than to observe the choice of key
identifier, KDF, and AEAD), so it is also assumed that it cannot generate an
Encapsulated Response.

### Differential Treatment

A relay MAY add information to requests if the client is aware of the nature of
the information that could be added.  The client does not need to be aware of
the exact value added for each request, but needs to know the range of possible
values the relay might use.  It is important to note that information added by
the relay can reduce the size of the anonymity set of clients at a gateway.

Moreover, relays MAY apply differential treatment to clients that engage in abusive
behavior, e.g., by sending too many requests in comparison to other clients,
or as a response to rate limits signalled from the gateway. Any such
differential treatment can reveal information to the gateway that would not
be revealed otherwise and therefore reduce the size of the anonymity set of
clients using a gateway. For example, if a relay chooses to rate limit or
block an abusive client, this means that any client requests which are not
treated this way are known to be non-abusive by the gateway. Clients should
consider the likelihood of such differential treatment and the privacy
risks when using a relay.

Some patterns of abuse cannot be detected without access to the request that
is made to the target. This means that only the gateway or target are in a
position to identify abuse. A gateway MAY send signals toward the relay to
provide feedback about specific requests. A relay that acts on this feedback
could - either inadvertently or by design - lead to clients being deanonymized.

### Denial of Service {#dos}

As there are privacy benefits from having a large rate of requests forwarded by
the same relay (see {{ta}}), servers that operate the Oblivious Gateway Resource
might need an arrangement with Oblivious Relay Resources. This arrangement might
be necessary to prevent having the large volume of requests being classified as
an attack by the server.

If a server accepts a larger volume of requests from a relay, it needs to
trust that the relay does not allow abusive levels of request volumes from
clients. That is, if a server allows requests from the relay to be exempt from
rate limits, the server might want to ensure that the relay applies a rate
limiting policy that is acceptable to the server.

Servers that enter into an agreement with a relay that enables a higher request
rate might choose to authenticate the relay to enable the higher rate.


### Traffic Analysis {#ta}

This document assumes that all communication between different Oblivious Client,
Oblivious Relay Resource, and Oblivious Gateway Resource is protected by HTTPS.  This protects information about which
resources are the subject of request and prevents a network observer from being
able to trivially correlate messages on either side of a relay.  However, it does
not mitigate traffic analysis by such network observers.

The time at which Encapsulated Request or response messages are sent can
reveal information to a network observer. Though messages exchanged between the
Oblivious Relay Resource and the Oblivious Gateway Resource might be sent in a
single connection, traffic analysis could be used to match messages that are
forwarded by the relay.

A relay could, as part of its function, add delays in order to increase the
anonymity set into which each message is attributed. This could latency to the
overall time clients take to receive a response, which might not be what some
clients want.

A relay that forwards large volumes of exchanges can provide better privacy by
providing larger sets of messages that need to be matched.

Traffic analysis is not restricted to network observers. A malicious Oblivious Relay Resource could
use traffic analysis to learn information about otherwise encrypted requests
and responses relayed between clients and gateways. An Oblivious Relay Resource terminates
TLS connections from clients, so they see message boundaries. This privileged
position allows for richer feature extraction from encrypted data, which might
improve traffic analysis.

Clients can use padding to reduce the effectiveness of traffic analysis.
Padding is a capability provided by binary HTTP messages; see {{Section 3.8 of
BINARY}}.

## Server Responsibilities

The Oblivious Gateway Resource can be operated by a different entity than the
Target Resource.  However, this means that the client needs to trust the
Oblivious Gateway Resource not to modify requests or responses.  This analysis
concerns itself with a deployment scenario where a single server provides both
the Oblivious Gateway Resource and Target Resource.

A server that operates both Oblivious Gateway and Target Resources is
responsible for removing request encryption, generating a response to the
Encapsulated Request, and encrypting the response.

Servers should account for traffic analysis based on response size or generation
time.  Techniques such as padding or timing delays can help protect against such
attacks; see {{ta}}.

If separate entities provide the Oblivious Gateway Resource and Target Resource,
these entities might need an arrangement similar to that between server and
relay for managing denial of service; see {{dos}}. It is also necessary to
provide confidentiality protection for the unprotected requests and responses,
plus protections for traffic analysis; see {{ta}}.

Nonsecure requests - such those with the "http" scheme as opposed to the "https"
scheme - SHOULD NOT be used if the Oblivious Gateway and Target Resources are
operated by different entities as that would expose both requests and response
to modification or inspection by a network attacker.


## Key Management

An Oblivious Gateway Resource needs to have a plan for replacing keys. This
might include regular replacement of keys, which can be assigned new key
identifiers. If an Oblivious Gateway Resource receives a request that contains a
key identifier that it does not understand or that corresponds to a key that has
been replaced, the server can respond with an HTTP 422 (Unprocessable Content)
status code.

A server can also use a 422 status code if the server has a key that corresponds
to the key identifier, but the Encapsulated Request cannot be successfully
decrypted using the key.

A server MUST ensure that the HPKE keys it uses are not valid for any other
protocol that uses HPKE with the "message/bhttp request" label.  Designers of
protocols that reuse this encryption format, especially new versions of this
protocol, can ensure key diversity by choosing a different label in their use of
HPKE.  The "message/bhttp response" label was chosen for symmetry only as it
provides key diversity only within the HPKE context created using the
"message/bhttp request" label; see {{repurposing-the-encapsulation-format}}.


## Replay Attacks {#replay}

A server is responsible for either rejecting replayed requests or ensuring that
the effect of replays does not adversely affect clients or resources.

Encrypted requests can be copied and replayed by the Oblivious Relay
resource. The threat model for Oblivious HTTP allows the possibility that an
Oblivious Relay Resource might replay requests. Furthermore, if a client sends
an Encapsulated Request in TLS early data (see {{Section 8 of TLS}} and
{{!RFC8470}}), a network-based adversary might be able to cause the request to
be replayed. In both cases, the effect of a replay attack and the mitigations
that might be employed are similar to TLS early data.

It is the responsibility of the application that uses Oblivious HTTP to either
reject replayed requests or to ensure that replayed requests have no adverse
affects on their operation.  This section describes some approaches that are
universally applicable and suggestions for more targeted techniques.

A client or Oblivious Relay Resource MUST NOT automatically attempt to retry a
failed request unless it receives a positive signal indicating that the request
was not processed or forwarded. The HTTP/2 REFUSED_STREAM error code (Section
8.1.4 of {{!RFC7540}}), the HTTP/3 H3_REQUEST_REJECTED error code (Section 8.1
of {{!QUIC-HTTP=I-D.ietf-quic-http}}), or a GOAWAY frame with a low enough
identifier (in either protocol version) are all sufficient signals that no
processing occurred. Connection failures or interruptions are not sufficient
signals that no processing occurred.

The anti-replay mechanisms described in {{Section 8 of TLS}} are generally
applicable to Oblivious HTTP requests. The encapsulated keying material (or
`enc`) can be used in place of a nonce to uniquely identify a request.  This
value is a high-entropy value that is freshly generated for every request, so
two valid requests will have different values with overwhelming probability.

The mechanism used in TLS for managing differences in client and server clocks
cannot be used as it depends on being able to observe previous interactions.
Oblivious HTTP explicitly prevents such linkability.

The considerations in {{!RFC8470}} as they relate to managing the risk of
replay also apply, though there is no option to delay the processing of a
request.

Limiting requests to those with safe methods might not be satisfactory for some
applications, particularly those that involve the submission of data to a
server. The use of idempotent methods might be of some use in managing replay
risk, though it is important to recognize that different idempotent requests
can be combined to be not idempotent.

Even without replay prevention, the server-chosen `response_nonce` field
ensures that responses have unique AEAD keys and nonces even when requests are
replayed.


### Use of Date for Anti-Replay

Clients SHOULD include a `Date` header field in Encapsulated Requests, unless
the Oblivious Gateway Resource does not use `Date` for anti-replay purposes.

Though HTTP requests often do not include a `Date` header field, the value of
this field might be used by a server to limit the amount of requests it needs to
track if it needs to prevent replay attacks.

An Oblivious Gateway Resource can maintain state for requests for a small window
of time over which it wishes to accept requests.  The Oblivious Gateway Resource
can store all requests it processes within this window.  Storing just the `enc`
field of a request, which should be unique to each request, is sufficient.  The
Oblivious Gateway Resource then rejects requests if the request is the same as
one that was previously answered within that time window, or if the `Date`
header field from the decrypted request is outside of the current time window.

Oblivious Gateway Resources SHOULD allow for the time it takes requests to
arrive from the client, with a time window that is large enough to allow for
differences in clocks.

Oblivious Gateway Resources MUST NOT treat the time window as secret
information. An attacker can actively probe with different values for the `Date`
field to determine the time window over which the server will accept responses.


### Correcting Clock Differences {#date-fix}

An Oblivious Gateway Resource can reject requests that contain a `Date` value
that is outside of its active window with a 400 series status code.  The problem
type {{!PROBLEM=I-D.ietf-httpapi-rfc7807bis}} of
"https://iana.org/assignments/http-problem-types#date" is defined to allow the
server to signal that the `Date` value in the request was unacceptable.

{{fig-date-reject}} shows an example response in HTTP/1.1 format.

~~~ http-message
HTTP/1.1 400 Bad Request
Date: Mon, 07 Feb 2022 00:28:05 GMT
Content-Type: application/problem+json
Content-Length: 128

{"type":"https://iana.org/assignments/http-problem-types#date",
"title": "date field in request outside of acceptable range"}
~~~
{: #fig-date-reject title="Example Rejection of Request Date Field"}

Disagreements about time are unlikely if both client and Oblivious Gateway
Resource have a good source of time; see {{?NTP=RFC5905}}. However, clock
differences are known to be commonplace; see Section 7.1 of
{{?CLOCKSKEW=DOI.10.1145/3133956.3134007}}.

Including a `Date` header field in the response allows the client to correct
clock errors by retrying the same request using the value of the `Date` field
provided by the Oblivious Gateway Resource.  The value of the `Date` field can
be copied if the request is fresh, with an adjustment based on the `Age` field
otherwise.  When retrying a request, the client MUST create a fresh encryption
of the modified request, using a new HPKE context.

~~~ aasvg
+---------+       +-------------------+      +----------+
| Client  |       | Relay and Gateway |      | Target   |
|         |       |     Resources     |      | Resource |
+----+----+       +----+-----------+--+      +----+-----+
     |                 |           |              |
     |                 |           |              |
     |  Request        |           |              |
     +============================>+------------->|
     |                 |           |              |
     |                 |           | 400 Response |
     |                 |           |       + Date |
     |<============================+<-------------+
     |                 |           |              |
     |  Request        |           |              |
     |  + Updated Date |           |              |
     +============================>+------------->|
     |                 |           |              |
~~~
{: #fig-retry-date title="Retrying with an Update Date Field"}

Intermediaries can sometimes rewrite the `Date` field when forwarding responses.
This might cause problems if the Oblivious Gateway Resource and intermediary
clocks differ by enough to cause the retry to be rejected.  Therefore, clients
MUST NOT retry a request with an adjusted date more than once.

Oblivious Gateway Resources that condition their responses on the `Date` header
field SHOULD either ensure that intermediaries do not cache responses (by
including a `Cache-Control` directive of `no-store`) or designate the response
as conditional on the value of the `Date` request header field (by including the
token "date" in a `Vary` header field).

Clients MUST NOT use the date provided by the Oblivious Gateway Resource for any
other purpose, including future requests to any resource.  Any request that uses
information provided by the Oblivious Gateway Resource might be correlated using
that information.


## Forward Secrecy

This document does not provide forward secrecy for either requests or
responses during the lifetime of the key configuration. A measure of
forward secrecy can be provided by generating a new key configuration
then deleting the old keys after a suitable period.

## Post-Compromise Security

This design does not provide post-compromise security for responses.

A client only needs to retain keying material that might be used compromise the
confidentiality and integrity of a response until that response is consumed, so
there is negligible risk associated with a client compromise.

A server retains a secret key that might be used to remove protection from
messages over much longer periods. A server compromise that provided access to
the Oblivious Gateway Resource secret key could allow an attacker to recover the
plaintext of all requests sent toward affected keys and all of the responses
that were generated.

Even if server keys are compromised, an adversary cannot access messages
exchanged by the client with the Oblivious Relay Resource as messages are
protected by TLS.  Use of a compromised key also requires that the Oblivious
Relay Resource cooperate with the attacker or that the attacker is able to
compromise these TLS connections.

The total number of affected messages affected by server key compromise can be
limited by regular rotation of server keys.


## Client Clock Exposure

Including a `Date` field in requests reveals some information about the client
clock.  This might be used to fingerprint clients {{UWT}} or to identify clients
that are vulnerable to attacks that depend on incorrect clocks.

Clients can randomize the value that they provide for `Date` to obscure the true
value of their clock and reduce the chance of linking of requests over time.
However, this increases the risk that their request is rejected as outside the
acceptable window.


# Privacy Considerations {#privacy}

One goal of this design is that independent client requests are only linkable by
the chosen key configuration. The Oblivious Relay and Gateway resources can link
requests using the same key configuration by matching KeyConfig.key\_id, or, if
the Target Resource is willing to use trial decryption, a limited set of key
configurations that share an identifier. An Oblivious Relay Resource can link
requests using the public key corresponding to KeyConfig.key\_id or via the
URI of the Oblivious Gateway Resource. We refer to this set of information as the gateway's
configuration.

Whether or not targets can link requests depends on how gateway configuration
information is produced and discovered by clients. Specifically, gateways can
maliciously construct configurations to track individual clients.

Ideally, all clients share a consistent view of the gateway configuration. The number
of different valid configurations can exponentially partition the anonymity set of
clients. For example, if there are two valid configurations, that would yield two
anonymity sets consisting of clients that used one configuration and clients that used
the other configuration. If the size of each set is large enough, this may not be
a significant loss of privacy in practice. Ensuring that many clients share
a configuration is necessary to provide privacy for clients.

A specific method for a client to acquire configurations is not included in this
specification. Applications using this design MUST provide accommodations to mitigate tracking
using gateway configurations. {{?CONSISTENCY=I-D.wood-key-consistency}} provides
options for ensuring that configurations are consistent between clients.


# Operational and Deployment Considerations {#deployment}

This section discusses various operational and deployment considerations.

## Performance Overhead

Using Oblivious HTTP adds both cryptographic and latency to requests relative to
a simple HTTP request-response exchange.  Deploying relay services that are on
path between clients and servers avoids adding significant additional delay due
to network topology.  A study of a similar system {{ODoH}} found that deploying
proxies close to servers was most effective in minimizing additional latency.


## Resource Mappings {#proxy-state}

This protocol assumes a fixed, one-to-one mapping between the Oblivious Relay
Resource and the Oblivious Gateway Resource. This means that any encrypted
request sent to the Oblivious Relay Resource will always be forwarded to the
Oblivious Gateway Resource. This constraint was imposed to simplify relay
configuration and mitigate against the Oblivious Relay Resource being used as
a generic relay for unknown Oblivious Gateway Resources. The relay will only
forward for Oblivious Gateway Resources that it has explicitly configured and
allowed.

It is possible for a server to be configured with multiple Oblivious Relay
Resources, each for a different Oblivious Gateway Resource as needed.  If the
goal is to support a large number of Oblivious Gateway Resources, clients might
be provided with a URI template {{?TEMPLATE=RFC6570}}, from which multiple
Oblivious Relay Resources could be constructed.


## Network Management

Oblivious HTTP might be incompatible with network interception regimes, such as
those that rely on configuring clients with trust anchors and intercepting TLS
connections.  While TLS might be intercepted successfully, interception
middleboxes devices might not receive updates that would allow Oblivious HTTP to
be correctly identified using the media types defined in {{media-types}}.

Oblivious HTTP has a simple key management design that is not trivially altered
to enable interception by intermediaries.  Clients that are configured to enable
interception might choose to disable Oblivious HTTP in order to ensure that
content is accessible to middleboxes.


# Repurposing the Encapsulation Format

The encrypted payload of an OHTTP request and response is a binary HTTP
message {{BINARY}}. Client and target agree on this encrypted payload type by
specifying the media type "message/bhttp" in the HPKE info string and HPKE
export context string for request and response encryption, respectively.

Future specifications may repurpose the encapsulation mechanism described in
{{hpke-encapsulation}}, provided that the content type of the encrypted
payload is appropriately reflected in the HPKE info and context strings. For
example, if a future specification were to use the encryption mechanism in
this specification for DNS messages, identified by the "application/dns-message"
media type, then the HPKE info string SHOULD be "application/dns-message
request" for request encryption, and the HPKE export context string should be
"application/dns-message response" for response encryption.


# IANA Considerations

IANA are request to update the "Media Types" registry at
<https://www.iana.org/assignments/media-types> with the registration information
in {{media-types}} for the media types "message/ohttp-req", "message/ohttp-res",
and "application/ohttp-keys".

IANA are requested to create a new entry in the "HTTP Problem Type" registry
established by {{!PROBLEM}}.

Type URI:
: https://iana.org/assignments/http-problem-types#date

Title:
: Date Not Acceptable

Recommended HTTP Status Code:
: 400

Reference:
: {{date-fix}} of this document


--- back


# Complete Example of a Request and Response

<!-- Generated using ohttp (https://github.com/martinthomson/ohttp):
RUST_LOG=ohttp cargo test -\-features nss,client,server -\-no-default-features -p ohttp -\-lib -\- -\-nocapture request_response
Note: "rust-hpke" doesn't log the client/sender keying material.
-->

A single request and response exchange is shown here. Binary values (key
configuration, secret keys, the content of messages, and intermediate values)
are shown in hexadecimal. The request and response here are minimal; the purpose
of this example is to show the cryptographic operations.  In this example, the
client is configured with the Oblivious Relay Resource URI of
`https://proxy.example.org/request.example.net/proxy`, and the proxy is
configured to map requests to this URI to the Oblivious Gateway URI
`https://example.com/oblivious/request`. The Target Resource URI, i.e., the
resource the client ultimately wishes to query, is `https://example.com`.

To begin the process, the Oblivious Gateway Resource generates a key pair.
In this example the server chooses DHKEM(X25519, HKDF-SHA256) and generates
an X25519 key pair {{?X25519=RFC7748}}. The X25519 secret key is:

~~~ hex-dump
3c168975674b2fa8e465970b79c8dcf09f1c741626480bd4c6162fc5b6a98e1a
~~~

The Oblivious Gateway Resource constructs a key configuration that includes the
corresponding public key as follows:

~~~ hex-dump
01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e
79815500080001000100010003
~~~

This key configuration is somehow obtained by the client. Then when a client
wishes to send an HTTP request of a GET request to the target `https://example.com`,
it constructs the following binary HTTP message:

~~~ hex-dump
00034745540568747470730b6578616d706c652e636f6d012f
~~~

The client then reads the Oblivious Gateway Resource key configuration and
selects a mutually supported KDF and AEAD. In this example, the client selects
HKDF-SHA256 and AES-128-GCM. The client then generates an HPKE sending context
that uses the server public key. This context is constructed from the following
ephemeral secret key:

~~~ hex-dump
bc51d5e930bda26589890ac7032f70ad12e4ecb37abb1b65b1256c9c48999c73
~~~

The corresponding public key is:

~~~ hex-dump
4b28f881333e7c164ffc499ad9796f877f4e1051ee6d31bad19dec96c208b472
~~~

And an `info` parameter of:

~~~ hex-dump
6d6573736167652f626874747020726571756573740001002000010001
~~~

Applying the Seal operation from the HPKE context produces an encrypted
message, allowing the client to construct the following Encapsulated Request:

~~~ hex-dump
010020000100014b28f881333e7c164ffc499ad9796f877f4e1051ee6d31bad1
9dec96c208b4726374e469135906992e1268c594d2a10c695d858c40a026e796
5e7d86b83dd440b2c0185204b4d63525
~~~

The client then sends this to the Oblivious Relay Resource in a POST request,
which might look like the following HTTP/1.1 request:

~~~ http-message
POST /request.example.net/proxy HTTP/1.1
Host: proxy.example.org
Content-Type: message/ohttp-req
Content-Length: 78

<content is the Encapsulated Request above>
~~~

The Oblivious Relay Resource receives this request and forwards it to the
Oblivious Gateway Resource, which might look like:

~~~ http-message
POST /oblivious/request HTTP/1.1
Host: example.com
Content-Type: message/ohttp-req
Content-Length: 78

<content is the Encapsulated Request above>
~~~

The Oblivous Gateway Resource receives this request, selects the key it
generated previously using the key identifier from the message, and decrypts the
message. As this request is directed to the same server, the Oblivious Gateway
Resource does not need to initiate an HTTP request to the Target Resource. The
request can be served directly by the Target Resource, which generates a minimal
response (consisting of just a 200 status code) as follows:

~~~ hex-dump
0140c8
~~~

The response is constructed by extracting a secret from the HPKE context:

<!-- ikm for HKDF extract -->
~~~ hex-dump
62d87a6ba569ee81014c2641f52bea36
~~~

The key derivation for the Encapsulated Response uses both the encapsulated KEM
key from the request and a randomly selected nonce. This produces a salt of:

~~~ hex-dump
4b28f881333e7c164ffc499ad9796f877f4e1051ee6d31bad19dec96c208b472
c789e7151fcba46158ca84b04464910d
~~~

The salt and secret are both passed to the Extract function of the selected KDF
(HKDF-SHA256) to produce a pseudorandom key of:

~~~ hex-dump
979aaeae066cf211ab407b31ae49767f344e1501e475c84e8aff547cc5a683db
~~~

The pseudorandom key is used with the Expand function of the KDF and an info
field of "key" to produce a 16-byte key for the selected AEAD (AES-128-GCM):

~~~ hex-dump
5d0172a080e428b16d298c4ea0db620d
~~~

With the same KDF and pseudorandom key, an info field of "nonce" is used to
generate a 12-byte nonce:

~~~ hex-dump
f6bf1aeb88d6df87007fa263
~~~

The AEAD `Seal()` function is then used to encrypt the response, which is added
to the randomized nonce value to produce the Encapsulated Response:

~~~ hex-dump
c789e7151fcba46158ca84b04464910d86f9013e404feea014e7be4a441f234f
857fbd
~~~

The Oblivious Gateway Resource constructs a response with the same content:

~~~ http-message
HTTP/1.1 200 OK
Date: Wed, 27 Jan 2021 04:45:07 GMT
Cache-Control: private, no-store
Content-Type: message/ohttp-res
Content-Length: 38

<content is the Encapsulated Response>
~~~

The same response might then be generated by the Oblivious Relay Resource which
might change as little as the Date header. The client is then able to use the
HPKE context it created and the nonce from the Encapsulated Response to
construct the AEAD key and nonce and decrypt the response.


# Acknowledgments
{: numbered="false"}

This design is based on a design for Oblivious DoH, described in
{{?ODOH=RFC9230}}. David Benjamin, Mark Nottingham, and Eric Rescorla made
technical contributions.
