---
title: "Binary Representation of HTTP Messages"
abbrev: Binary HTTP Messages
docname: draft-thomson-http-binary-message-latest
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

informative:


--- abstract

This document defines a binary format for representing HTTP messages.


--- middle

# Introduction

This document defines a simple format for representing an HTTP message
({{!HTTP=I-D.ietf-httpbis-semantics}}), either request or response. This allows
for the encoding of HTTP messages that can be conveyed outside of an HTTP
protocol. This enables the application of transformations to entire messages,
including the application of encryption and authentication.

This format is informed by the structure of HTTP/2 ({{?H2=RFC7540}}) and HTTP/3
({{?H3=I-D.ietf-quic-http}}), but omits header compression ({{?HPACK=RFC7541}},
{{?QPACK=I-D.ietf-quic-qpack}}) and does not include a generic framing layer.

This provides an alternative to the `message/http` content type defined in
{{?MESSAGING=I-D.ietf-httpbis-messaging}}.  A binary format permits more efficient encoding and processing of content.  A binary format also reduces exposure to security problems related to processing of HTTP


# Conventions and Definitions

{::boilerplate bcp14}

This document uses terminology from HTTP ({{!HTTP}}).

This document uses notation from QUIC ({{!QUIC=I-D.ietf-quic-transport}}).


# Format

An HTTP message is split into five sections, following the structure defined in
Section 6 of {{!HTTP}}:

1. Framing indicator. This format uses a single integer to describe framing, which describes
   whether the message is a request or response and how subsequent sections are
   formatted; see {{framing}}

2. Control data. For a request, this contains the request method and target.
   For a response, this contains the status code.

3. Header section.  This contains zero or more header fields.

4. Content.  This is a sequence of zero or more bytes.

5. Trailer section.  This contains zero or more trailer fields.

A response message can include multiple informational responses, which causes
the control data and header section to be repeated.

All lengths and numeric values are encoded using the variable-length integer
encoding from {{!QUIC}}.


## Known Length Messages

A message that has a known length at the time of construction uses the
format shown in {{format-known-length}}.

~~~
Message with Known-Length {
  Framing (i) = 0..1,
  Known-Length Informational Response (..) ...,
  Control Data (..),
  Known-Length Field Section (..),
  Known-Length Content (..),
  Known-Length Field Section (..),
}

Known-Length Field Section {
  Length (i) = 2..,
  Field Line (..) ...,
}

Known-Length Content {
  Content Length (i),
  Content (..)
}

Known-Length Informational Response {
  Informational Response Control Data (..),
  Known-Length Field Section (..),
}
~~~
{: #format-known-length title="Known-Length Message"}

That is, a known-length message consists of a framing indicator, a block of
control data that is formatted according to the value of the framing indicator,
a header field section with a length prefix, binary content with a length
prefix, and a trailer field section with a length prefix.

Response messages that contain informational status codes result in a different
structure; see {{informational}}.

Fields in the header and trailer field sections consist of a length-prefixed
name and length-prefixed value. Both name and value are sequences of bytes that
cannot be zero length.

The format allows for the message to be truncated before any of the length
prefixes that precede the field sections or content. This reduces the overall
message size. A message that is truncated at any other point is invalid; see
{{invalid}}.

The use of variable-length integers means that there is a limit of 2^62-1 bytes
for each field section and the message content.


## Indeterminate Length Messages

A message that is constructed without encoding a known length for each section
uses the format shown in {{format-indeterminate-length}}:

~~~
Indeterminate-Length Message  {
  Framing Indicator (i) = 2..3,
  Indeterminate-Length Informational Response (..) ...,
  Control Data (..),
  Indeterminate-Length Field Section (..),
  Indeterminate-Length Content (..) ...,
  Indeterminate-Length Field Section (..),
}

Indeterminate-Length Content {
  Indeterminate-Length Content Chunk (..) ...,
  Content Terminator (i) = 0,
}

Indeterminate-Length Content Chunk {
  Chunk Length (i) = 1..,
  Chunk (..)
}

Indeterminate-Length Field Section {
  Field Line (..) ...,
  Content Terminator (i) = 0,
}

Indeterminate-Length Informational Response {
  Informational Response Control Data (..),
  Indeterminate-Length Field Section (..),
}
~~~
{: #format-indeterminate-length title="Indeterminate-Length Message"}

That is, an indeterminate length consists of a framing indicator, a block of
control data that is formatted according to the value of the framing indicator,
a header field section that is terminated by a zero value, any number of
non-zero-length chunks of binary content, a zero value, and a trailer field
section that is terminated by a zero value.

Response messages that contain informational status codes result in a different
structure; see {{informational}}.

Indeterminate-length messages can be truncated in a similar way as known-length
messages. Truncation occurs after the control data, or after the Content
Terminator field that ends a field section or sequence of content chunks. A
message that is truncated at any other point is invalid; see {{invalid}}.

Indeterminate-length messages uses the same encoding for fields as known-length
messages; see {{fields}}.


## Framing Indicator {#framing}

The start of each is a framing indicator that is a single integer that
describes the structure of the subsequent sections. The framing indicator can
take just four values:

* A value of 0 describes a request of known length.
* A value of 1 describes a response of known length.
* A value of 2 describes a request of indeterminate length.
* A value of 3 describes a response of indeterminate length.

Other values cause the message to be invalid; see {{invalid}}.


## Request Control Data

The control data for a request message includes four values that correspond to
the values of the `:method`, `:scheme`, `:authority`, and `:path` pseudo-header
fields described in HTTP/2 {{!H2}}. These fields are encoded, each with a
length prefix, in the order listed.

The format of request control data is shown in {{format-request-control-data}}.

~~~
Request Control Data {
  Method Length (i),
  Method (..),
  Scheme Length (i),
  Scheme (..),
  Authority Length (i),
  Authority (..),
  Path Length (i),
  Path (..),
}
~~~
{: #format-request-control-data title="Format of Request Control Data"}


## Response Control Data

The control data for a request message includes a single field that corresponds
to the `:status` pseudo-header field in HTTP/2 {{!H2}}. This field is encoded
as a single variable length integer, not a decimal string.

The format of final response control data is shown in
{{format-response-control-data}}.

~~~
Final Response Control Data {
  Status Code (i) = 200..599,
}
~~~
{: #format-response-control-data title="Format of Final Response Control Data"}


### Informational Status Codes {#informational}

This format supports informational status codes (see Section 15.2 of
{{!HTTP}}). Responses that include information status codes are encoded by
repeating the response control data and associated header field section until
the a final status code is encoded.

The format of the informational response control data is shown in
{{format-informational}}.

~~~
Informational Response Control Data {
  Status Code (i) = 100..199,
}
~~~
{: #format-informational title="Format of Informational Response Control Data"}

A response message can include any number of informational responses. If the
response control data includes an informational status code (that is, a value
between 100 and 199 inclusive), the control data is followed by a header field
section (encoded with known- or indeterminate- length according to the framing
indicator). After the header field section, another response control data block
follows.


## Header and Trailer Fields {#fields}

Header and trailer field sections consist of zero or more field lines; see
Section 5 of {{!HTTP}}. The format of a field section depends on whether the
message is known- or intermediate-length.

Each field line includes a name and a value. Both the name and value are
non-zero length sequences of bytes. The format of a field line is shown in
{{format-field-line}}.

~~~
Field Line {
  Name Length (i) = 1..,
  Name (..),
  Value Length (i) = 1..,
  Value (..),
}
~~~
{: #format-field-line title="Format of a Field Line"}

For field names, byte values that are not permitted in an HTTP field name cause
the message to be invalid; see Section 5.1 of {{!HTTP}} and {{invalid}}. In
addition, values from the ASCII uppercase range (0x41-0x5a inclusive) MUST be
translated to lowercase values (0x61-0x7a) when encoding messages. A recipient
MUST treat a message containing field names with bytes in the range 0x41-0x5a
as invalid; see {{invalid}}.

For field values, byte values that are not permitted in an HTTP field value
cause the message to be invalid; see Section 5.5 of {{!HTTP}} and {{invalid}}.

The same field name can be repeated in multiple field lines; see Section 5.2 of
{{!HTTP}} for the semantics of repeated field names and rules for combining
values.

Like HTTP/2, this format has an exception for the combination of multiple
instances of the `Cookie` field. Instances of fields with the ASCII-encoded
value of `cookie` are combined using a semicolon octet (0x3b) rather than a
comma; see Section 8.1.2.5 of {{!H2}}.

This format provides fixed locations for content that would be carried in
HTTP/2 pseudo-fields. Therefore, there is no need to include values for
`:method`, `:scheme`, `:authority`, `:path`, or `:status`. Fields that contain
one of these names cause the message to be invalid; see {{invalid}}.
Pseudo-fields that are defined by protocol extensions can be included.
Pseudo-fields MUST precede other fields, if present.


## Content

The content of messages is a sequence of bytes of any length. Though a
known-length message has a limit, this limit is large enough that it is
unlikely to be a practical limitation. There is there is no limit to an
indeterminate length message.

Omitting content by truncating a message is only possible if the content is
zero-length.


# Invalid Messages {#invalid}

This document describes a number of ways that a message can be invalid. Invalid
messages MUST NOT be processed except to log an error and produce an error
response.

The format is designed to allow incremental processing. Implementations need to
be aware of the possibility that an error might be detected after performing
incremental processing.


# Examples

TODO


# "message/bhttp" Media Type {#media-type}


The message/http media type can be used to enclose a single HTTP request or
response message, provided that it obeys the MIME restrictions for all
"message" types regarding line length and encodings.

Type name:

: message

Subtype name:

: bhttp

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

Many of the considerations that apply to HTTP message handling apply to this
format; see Section 17 of {{!HTTP}} and Section 11 of {{!MESSAGING}} for common
issues in handling HTTP messages.

Strict parsing of the format with no tolerance for errors can help avoid a
number of attacks. However, implementations still need to be aware of the
possibility of resource exhaustion attacks that might arise from receiving
large messages, particularly those with large numbers of fields.

The format is designed to allow for minimal state when translating for use with
HTTP proper. However, producing a combined value for fields, which might be
necessary for the `Cookie` field when translating this format (like HTTP/1.1
{{!MESSAGING}}), can require the commitment of resources. Implementations need
to ensure that they aren't subject to resource exhaustion attack from a
maliciously crafted message.


# IANA Considerations

Please add the "Media Types" registry at
<https://www.iana.org/assignments/media-types> with the registration
information in {{media-type}} for the media type "message/bhttp".


--- back

# Acknowledgments
{: numbered="false"}

TODO: credit where credit is due.
