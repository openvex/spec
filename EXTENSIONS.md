# OpenVEX Extensions

**Status:** Draft (TLP:CLEAR)
**Target Version:** OpenVEX v1.0
**Authors:**

- Adolfo García Veytia (@puerco)
- Carlos Tadeu Panato Jr (@cpanato)
- Guilherme Macedo (@macedogm)

## Overview

OpenVEX is one of the implementations of Vulnerability Exploitability
eXchange (VEX). Like CSAF, SPDX and CycloneDX, it adheres to the
[Minimum Requirements for VEX] published by the VEX Working Group
originally coordinated by CISA. One of the core principles of the
project is _do not break upstream VEX_: an OpenVEX document must remain
a valid VEX document, understandable by any implementation that conforms
to the minimum requirements.

Over the years, users have asked for OpenVEX to carry information beyond the
minimum elements of VEX. Rescoring a vulnerability in the context of a specific
product ([OPEV-0016]) is the most recent example. The pledge not to break
upstream VEX has so far kept these capabilities out of the specification.

This document defines a mechanism to extend OpenVEX documents with additional
data without altering the core format. It lets implementers, vendors and the
OpenVEX project itself publish _extensions_ that enrich VEX statements while
documents remain backwards compatible and processable by tools that know nothing
about the extension.

The mechanism builds on the fact that OpenVEX documents are [JSON-LD][JSON-LD].
An extension is a JSON-LD context that binds a short prefix to a namespace. A
document opts into the extension by listing the context, and carries the
extension data in prefixed fields placed next to the core OpenVEX fields.

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, MAY and OPTIONAL in
this document are to be interpreted as described in [RFC 2119].

## Design Principles

1. **Strip invariant:** Removing every extension field from a document MUST
   leave a valid OpenVEX document whose VEX meaning is unchanged. Extension data
   enriches statements, it never carries part of their core meaning.
2. **Backwards compatible:** Consumers that do not implement extensions MUST be
   able to process extended documents without errors.
3. **Decentralized:** Anyone can publish an extension under a namespace they
   control. No registry is required.
4. **Valid linked data:** Extended documents are valid JSON-LD. Extension data
   expands to proper IRIs and joins the same graph as the core OpenVEX terms.
5. **Explicit:** A document declares every extension it uses. Parsers route
   extension data to handlers based on that declaration, never on guesswork.

## Definitions

- **Extension:** A named set of additional fields that can appear in an OpenVEX
  document, published together with the artifacts described in [Defining an
  Extension](#defining-an-extension).
- **Extension IRI:** The IRI that identifies an extension globally and from
  which its context document can be retrieved. For example
  `https://example.com/ext/myext/v1`.
- **Extension Context:** The JSON-LD context document served at the extension
  IRI. It binds the extension prefix and defines the types of the extension's
  terms.
- **Prefix:** The short label, such as `myext`, that an extension context binds
  to its namespace. In documents, extension fields are written as `prefix:field`.
- **Extension Point:** A location in an OpenVEX document where extension fields
  MAY appear. See [Extension Points](#extension-points).
- **Extension-aware Consumer:** A tool that implements this specification and
  has a handler for at least one extension. A consumer that implements this
  specification but has no handler for a given extension is _unaware_ of that
  extension (not necesarily incompatible).

## Document Format

### Declaring Extensions

A document declares the extensions it uses by listing their extension IRIs in
its `@context` field. When a document uses extensions, `@context` becomes an
array. The array MUST contain the OpenVEX context IRI. Every other entry
declares one extension. Producers SHOULD place the OpenVEX context first.

```json
"@context": [
  "https://openvex.dev/ns/v0.2.0",
  "https://example.com/ext/myext/v1"
]
```

An entry SHOULD be the extension IRI as a string. An entry MAY instead be an
inline JSON-LD context object that binds the prefix to the extension namespace,
which is the extension IRI followed by `#`:

```json
"@context": [
  "https://openvex.dev/ns/v0.2.0",
  { "myext": "https://example.com/ext/myext/v1#" }
]
```

The inline form yields the correct IRIs for JSON-LD processors but carries none
of the type information from the extension context. It is intended for
experiments and for extensions that have not published a context yet.

The order of the entries has no effect on the meaning of the document. JSON-LD
processes contexts in sequence and lets a later definition override an earlier
one, but since extensions MUST NOT redefine core terms (see
[Constraints on Extensions](#constraints-on-extensions)), the core and
extension contexts never compete for a term. Placing the OpenVEX context first
is a convention for readability and deterministic output, not a requirement
consumers rely on.

A document that uses no extensions MAY keep the string form of `@context` defined
by the core specification.

### Extension Fields

Extension data is carried in fields whose key is the extension prefix, a colon,
and a field name: `myext:ticket`. Extension fields are placed at the same level
as the core fields of the extension point they belong to. They are not wrapped
in a container object.

Nested objects and arrays of objects inside an extension field keep the prefix
on every key:

```json
"review:owner": {
  "review:name": "Example Security Team",
  "review:contact": "mailto:security@example.com"
}
```

An extension MAY scope the definitions of nested terms to the field that
contains them (see [Nested Fields](#nested-fields)).

Values are ordinary JSON values. The extension context MAY type them (as
`xsd:dateTime`, `@id`, `@list` and so on) so that JSON-LD processors interpret
them correctly. Documents are not changed by the presence or absence of typing.

### Extension Points

Extension fields MAY appear in the following structures. Each extension states
which of these points it uses.

| Extension Point | Structure | Notes |
| --- | --- | --- |
| `document` | The document object | Data about the document as a whole, such as a policy under which it was issued. |
| `statement` | Each entry in `statements` | Data about the assertion, such as a rescoring or triage details. |
| `vulnerability` | The `vulnerability` object of a statement | Data about the vulnerability in the context of the statement. |
| `product` | Each entry in `products` | Data about a product. |
| `subcomponent` | Each entry in `subcomponents` | Data about a subcomponent of a product. |

Extension fields MUST NOT appear anywhere else. In particular they MUST NOT
appear inside the `hashes` and `identifiers` maps, whose keys are a fixed
catalog.

### Example

The following document uses a fictitious extension, `myext`, published by a
third party at `https://example.com/ext/myext/v1`. The extension has two
fields: the policy under which a document was issued, at the `document`
extension point, and the ticket tracking a statement, at the `statement`
extension point.

```json
{
  "@context": [
    "https://openvex.dev/ns/v0.2.0",
    "https://example.com/ext/myext/v1"
  ],
  "@id": "https://openvex.dev/docs/example/vex-ext-0001",
  "author": "Example Security Team",
  "role": "Document Creator",
  "timestamp": "2026-05-07T18:02:03Z",
  "version": 1,
  "myext:policy": "https://example.com/security/review-policy",
  "statements": [
    {
      "vulnerability": {
        "name": "CVE-2026-0001"
      },
      "products": [
        {
          "@id": "pkg:oci/example-api@sha256%3Aabc123?repository_url=ghcr.io/example/example-api",
          "subcomponents": [
            { "@id": "pkg:apk/wolfi/libfoo@1.4.2-r0" }
          ]
        }
      ],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "myext:ticket": "https://example.com/tickets/SEC-8812"
    }
  ]
}
```

A consumer unaware of the `myext` extension reads a regular OpenVEX document
with one `not_affected` statement. A JSON-LD processor expands `myext:ticket`
to `https://example.com/ext/myext/v1#ticket` next to the core `openvex:` terms.
An extension-aware consumer hands the `myext:policy` field of the document
and the `myext:ticket` field of the statement to its handler for that
extension.

The examples in this document use `myext` and other fictitious extensions to
illustrate the mechanism. This document does not define any extension.
[Appendix A](#appendix-a-a-proposed-extension-expressed-with-this-mechanism)
shows how a real proposal would look when expressed with it.

## Defining an Extension

An extension is published as a set of artifacts under the control of its
author.

### Extension IRI

The extension IRI identifies the extension. It MUST be an absolute IRI under a
domain the author controls, and it MUST dereference to the extension context.
Serving the context requires answering requests for `application/ld+json` with
the context document itself, not with an HTML page or a redirect to one.

Extensions published by the OpenVEX project use the following namespace:

`https://openvex.dev/ext/[name]/v[major]`

with the artifacts kept in this repository under `ext/[name]/v[major]/`,
mirroring the layout of the core context under `ns/`.

### Versioning

The major version is part of the extension IRI. A change that alters the
meaning of an existing field, removes a field or changes a value type MUST be
published under a new IRI. Additions of optional fields MAY be published under
the same IRI.

Two major versions of an extension are two different extensions. Because they
would normally bind the same prefix, a document can only declare one of them
(see [Prefix Collisions](#prefix-collisions)).

### Extension Context

The extension context is a JSON-LD 1.1 context document. It MUST:

- be a JSON object with a single top-level `@context` key,
- declare `"@version": 1.1`,
- bind exactly one prefix to the extension namespace, which is the extension
  IRI followed by `#`,
- define its terms keyed by their compact IRI, so that the keys in the context
  are the same strings that appear in documents.

It SHOULD type every term. Types are drawn from XML Schema datatypes, `@id`
for links, container declarations such as `@list`, or label types defined by
the extension itself in the style of the core context's `vexStatus`.

The context for the `myext` example above:

```json
{
  "@context": {
    "@version": 1.1,
    "myext": "https://example.com/ext/myext/v1#",

    "myext:policy": { "@type": "@id" },
    "myext:ticket": { "@type": "@id" }
  }
}
```

A context defines what a term means and how its value is typed. It does not
say where the term may appear: the definition of `myext:ticket` applies
wherever that key occurs. Which extension points a field belongs to is stated
in the extension's [specification text](#specification-text) and enforced by
its [JSON schema](#json-schema).

### Nested Fields

When an extension field holds an object, the nested keys keep the prefix and
need their own term definitions. An extension MAY define them at the top level
of its context, or it MAY scope them to the containing field with a
property-scoped context, which documents the nesting in the context itself.

The following fictitious `review` extension records who owns a statement. Its
`review:owner` field holds an object with a name and a contact:

```json
"status": "not_affected",
"review:owner": {
  "review:name": "Example Security Team",
  "review:contact": "mailto:security@example.com"
}
```

Its context defines `review:name` and `review:contact` inside the definition
of `review:owner`:

```json
{
  "@context": {
    "@version": 1.1,
    "xsd": "http://www.w3.org/2001/XMLSchema#",
    "review": "https://example.com/ext/review/v1#",

    "review:owner": {
      "@context": {
        "review:name":    { "@type": "xsd:string" },
        "review:contact": { "@type": "@id" }
      }
    }
  }
}
```

JSON-LD processors apply the scoped definitions only while inside
`review:owner`. The prefix binding itself remains global, so a `review:name`
key placed elsewhere still expands to an IRI in the extension namespace, just
without the scoped typing. Scoping therefore documents the intended structure
for linked data tooling but it does not replace the extension's JSON schema as
the check that fields appear where they belong.

An extension MUST NOT scope its terms under a core term such as `statements`
or `vulnerability`. Doing so redefines the core term, and since JSON-LD
replaces rather than merges term definitions, the last declared extension
would silently override the scoping of every other one.

### Specification Text

An extension MUST be accompanied by a human readable specification that states:

- the extension IRI and prefix
- the extension points it uses
- every field, its type, whether it is required within the extension, and its
  meaning
- the allowed values of any field with a fixed vocabulary
- any rules the extension imposes on its own data across extension points
- whether extension data at the `document` level applies to the document's
  statements (see [Data Inheritance](#data-inheritance)).

For the `myext` example, the field listing would be:

| Field | Extension Point | Type | Required |
| --- | --- | --- | --- |
| `myext:policy` | `document` | IRI | ✕ |
| `myext:ticket` | `statement` | IRI | ✓ |

### JSON Schema

An extension SHOULD publish a JSON schema for its data at each extension point
it uses. The schema describes the extension fields with their prefix, as they
appear in documents. The core OpenVEX schema does not validate extension data
(see [Validation](#validation)).

## Prefixes

### Syntax

A prefix MUST match `^[a-z][a-z0-9]*$`. It MUST NOT be one of the prefixes
bound by the core context (`openvex`, `xsd`, `rdfs`), and it MUST NOT be a URI
scheme name such as `http`, `https` or `urn`, since a key beginning with one of
those would be indistinguishable from an absolute IRI.

Extensions in the OpenVEX namespace use as prefix the `[name]` segment of their
extension IRI. Third party extensions SHOULD do the same when their IRI has a
suitable segment. The prefix is however always taken from the extension
context, never derived from the IRI by consumers.

### Binding

A prefix is bound within a single document by the contexts the document
declares. The same prefix MAY be bound to different namespaces in different
documents. Consumers MUST NOT assume a fixed prefix for an extension,
extensions are matched by IRI and learn the prefix from the context.

### Prefix Collisions

A document MUST NOT declare two contexts that bind the same prefix. Consumers
MUST reject such a document.

## Processing

### Producers

A producer that emits extension fields:

- MUST declare the extension in `@context`
- MUST place extension fields only at the extension points the extension
  specifies
- MUST NOT emit fields with a prefix that is not bound by a declared context
- SHOULD NOT declare extensions for which it emits no data

### Consumers Unaware of an Extension

A consumer that encounters a declared extension it has no handler for:

- MUST NOT reject the document because of it
- MUST ignore the extension's fields when interpreting the VEX content
- SHOULD preserve the extension's fields and its `@context` entry unchanged
  when it writes the document back out, so that extension data survives
  tools that do not understand it.

These rules apply equally to consumers that do not implement this
specification at all: for them, a prefixed key is an unknown field, and the
core specification already requires unknown fields to be tolerated.

### Extension-aware Consumers

An extension-aware consumer holds a set of handlers, each identified by its
extension IRI. When parsing a document it:

1. Reads the `@context` array. It identifies the OpenVEX context by its IRI,
   wherever it appears, and skips it. For every other entry, it determines the
   extension IRI: the string itself or (for an inline object) the bound
   namespace with its trailing `#` or `/` removed. Consumers MUST NOT rely on
   the position of the OpenVEX context in the array.
2. Looks each extension IRI up among its handlers. For a match, it binds the
   handler's prefix for this document.
3. Rejects the document if two declared extensions bind the same prefix.
4. At each extension point, groups the fields by prefix. Fields whose prefix is
   bound to a handler are passed to that handler, which decodes them into a
   typed value. Fields whose prefix is bound to a declared but unhandled
   extension are preserved as opaque data.
5. Fields whose prefix is not bound by any declared context are preserved as
   opaque data and SHOULD be reported as a warning. They MUST NOT be routed to
   a handler, even if a handler happens to use that prefix. A consumer MAY offer
   a strict mode in which such fields are an error.

Handlers decode the data at one extension point in isolation. Rules that span
extension points or depend on core fields are checked after the whole document
has been parsed.

When writing a document, an extension-aware consumer MUST ensure `@context`
declares every extension for which the document carries data, adding entries
as needed. It SHOULD NOT remove declarations it did not add. Extension fields
with no data MUST be omitted.

### Merging Documents

When tools merge documents, the `@context` of the result is the union of the
input contexts, with the OpenVEX context first. If two inputs bind the same
prefix to different namespaces, the merge MUST fail. Statements carried over
from an input keep their extension fields.

### Data Inheritance

The core specification lets statements inherit some document level values, such
as timestamps. Extension data does not inherit by default: fields at the
`document` extension point say something about the document, not about each
statement. An extension MAY define inheritance for its own fields, in which
case it MUST state the rule in its specification text and handle it in its
handlers.

## Constraints on Extensions

To keep the strip invariant, an extension:

- MUST NOT change the meaning, allowed values or requiredness of any core
  OpenVEX field
- MUST NOT be required to interpret the VEX status, justification or impact of
  a statement
- MUST NOT redefine or shadow a core term in its context
- MUST NOT carry a second copy of core data under its own prefix

An extension that becomes widely adopted may be proposed for inclusion in the
core specification through an OPEV. Graduation moves its fields into the core
context without prefixes, which is a new version of the core specification.

## Validation

The core OpenVEX JSON schema pre v1.0 sets `additionalProperties: false` on
every object, which rejects extension fields. The schema is therefore amended
to admit keys matching the extension field pattern at each of the five extension
points:

```json
"patternProperties": {
  "^[a-z][a-z0-9]*:": {}
}
```

The core schema does not check that a prefix is declared or that the data is
well formed. That validation is layered:

1. The core schema validates the core fields and admits extension fields at
   extension points.
2. The processing rules above check that every prefix in use is declared.
3. The extension's own JSON schema, when published, validates the extension
   data at each extension point.

## Changes to the Core Specification

Adopting this document requires the following changes to the OpenVEX
specification and its artifacts:

- `@context` accepts an array that contains the OpenVEX context IRI. The field
  description and the JSON schema change accordingly.
- The JSON schema admits extension fields at the five extension points as
  described in [Validation](#validation).
- The "OpenVEX and JSON-LD" section links to this document. Its existing
  "VEX Extensions" subsection, which describes how OpenVEX extends the VEX
  minimum requirements, is renamed to avoid confusion with extensions as
  defined here.
- The OpenVEX context and the extension contexts are served at their IRIs as
  JSON-LD, with the top level `@context` wrapper required of remote contexts.

## Open Questions

- Whether `subcomponent` should be an extension point from the start or added
  on demand.
- Whether to allow a `patternProperties` value stricter than `{}` in the core
  schema, for example requiring extension values to be non-null.
- How official extensions are proposed and reviewed: through an OPEV each, or
  through a lighter process in this repository.

## Appendix A: A Proposed Extension Expressed With This Mechanism

This appendix is informative. It shows how the vulnerability rating data
proposed in [OPEV-0016] would look if published as an extension. It does not
define a rating extension, reserve the `rating` prefix or the IRI used below,
or prejudge the outcome of that proposal. Whether and how a rating extension
is published is decided by the proposal's own process.

OPEV-0016 proposes a per statement object with the source of a rating and a
list of severities, each with a type and a score. As an extension it would use
the `statement` extension point, bind the prefix `rating` and carry the data
in two prefixed fields:

```json
{
  "@context": [
    "https://openvex.dev/ns/v0.2.0",
    "https://openvex.dev/ext/rating/v1"
  ],
  "@id": "https://openvex.dev/docs/example/vex-9fb3463de1b57",
  "author": "Wolfi J Inkinson",
  "role": "Document Creator",
  "timestamp": "2026-05-07T18:02:03Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "name": "CVE-2025-68121"
      },
      "products": [
        {
          "@id": "pkg:golang/github.com/rancher/rke2@v1.29.15+rke2r1",
          "subcomponents": [
            { "@id": "pkg:golang/stdlib@v1.23.6" }
          ]
        }
      ],
      "status": "affected",
      "rating:source": {
        "rating:name": "Acme Security Team",
        "rating:url": "https://www.example.com/cves/cve-2025-68121.html"
      },
      "rating:severities": [
        {
          "rating:type": "cvss_v4",
          "rating:score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
        },
        {
          "rating:type": "ssvc_v2",
          "rating:score": "SSVCv2/E:P/A:Y/T:P/P:M/B:M/M:L/D:T/2026-05-07T13:36:27Z/"
        },
        {
          "rating:type": "sev",
          "rating:score": "medium"
        }
      ]
    }
  ]
}
```

Stripping the two `rating:` fields leaves a plain `affected` statement, which
is what a consumer unaware of the extension reads. The extension context would
type the severities as an ordered list and the source URL as a link, with the
nested terms scoped to the field that contains them:

```json
{
  "@context": {
    "@version": 1.1,
    "xsd": "http://www.w3.org/2001/XMLSchema#",
    "rating": "https://openvex.dev/ext/rating/v1#",

    "rating:source": {
      "@context": {
        "rating:name": { "@type": "xsd:string" },
        "rating:url":  { "@type": "@id" }
      }
    },
    "rating:severities": {
      "@container": "@list",
      "@context": {
        "rating:type":  { "@type": "rating:severityType" },
        "rating:score": { "@type": "xsd:string" }
      }
    },

    "rating:severityType": { "@id": "rating:severityType", "@type": "xsd:string" }
  }
}
```

The allowed severity types and the format of each score are the extension's
own business. They would be listed in its specification text and enforced by
its JSON schema and handlers, not by the core OpenVEX schema.

## Revisions

| Date | Revision |
| --- | --- |
| 2026-10-29 | First draft. |

## Sources

- [JSON-LD 1.1][JSON-LD], W3C Recommendation.
- [OPEV-0016]: Vulnerability severity rating, the motivating proposal.
- [Minimum Requirements for VEX], published by CISA.
- [RFC 2119]: Key words for use in RFCs to Indicate Requirement Levels.

[JSON-LD]: https://www.w3.org/TR/json-ld11/
[Minimum Requirements for VEX]: https://www.cisa.gov/sites/default/files/2023-04/minimum-requirements-for-vex-508c.pdf
[OPEV-0016]: https://github.com/openvex/community/pull/24
[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119
