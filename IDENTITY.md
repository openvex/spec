# OpenVEX Identity Data Structure

**Status:** Draft
**Target:** OpenVEX v1
**Author:** Adolfo García Veytia (@puerco)

> [!CAUTION]
> This document is written to be merged
> into the OpenVEX specification as a section next to the product and
> vulnerability data structures. Until then it lives here as a standalone draft.

---

## Overview

OpenVEX records actors involved in a document in free form string fields. The
document `author`, the statement `supplier` and the document `tooling` fields
all take a string that the specification does not structure beyond suggesting
that it "should ideally be a machine readable identifier". In practice the
field holds anything from a person's name to an email address to a URL, and
consumers cannot tell which.

This has made the field unsuitable for the uses the project now needs. An
author string cannot be tied to the identity that signed the document, to a
[Sigstore] certificate, to a DID or to an organization record. Proposed features
such as multi-stakeholder approval of statements and inclusion records need to
name actors in a way that other systems can match and verify.

This document defines an `identity` data structure for OpenVEX v1 and makes
the fields that name actors accept it. The change is additive: every field
that takes an identity continues to accept the string form it takes today.

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, MAY and OPTIONAL in
this document are to be interpreted as described in [RFC 2119].

## Identity Data Structure

An identity names an actor: a person, an organization, a tool or an AI agent.
The structure
is shared by every field in OpenVEX that refers to an actor and is designed to
be matched against identities held by other systems, such as signature
verification policies, identity providers or organization directories.

The optional `@id` field takes an [IRI][IRI] that identifies the actor
globally. It makes the identity referenceable within the document and
addressable from other documents. Typical values are a `mailto:` IRI, a
[DID][DID], or an HTTPS URL under the actor's control.

The `identifiers` map lists the actor's identifiers in external systems, keyed
by identifier type. As with product identifiers, an identity SHOULD carry as
many identifiers as are known, since each one gives consumers another way to
match the actor.

### Example Identity Struct

```json
{
  "@id": "mailto:security@example.com",
  "name": "Example Security Team",
  "type": "organization",
  "identifiers": {
    "email": "security@example.com",
    "url": "https://example.com/security",
  }
}
```

### Identity Fields

| Field | Required | Description |
| --- | --- | --- |
| @id | ✕ | [IRI][IRI] identifying the actor globally. When present it is the canonical identifier of the actor. |
| name | ✕ | Human readable name of the actor. Not intended for matching. |
| type | ✕ | The kind of actor. One of the labels in the [Identity Types](#identity-types) table. |
| identifiers | ✕ | Map of identifiers of the actor in external systems. The key is the identifier type (see the [Identity Identifier Types](#identity-identifier-types) table) and the value the identifier. |

All fields are optional but an identity MUST carry at least one of `@id`,
`name` or `identifiers`.

### Identity Types

| Label | Description |
| --- | --- |
| `person` | An individual. |
| `organization` | A company, team, project or any other group acting as one. |
| `tool` | Software or an automated process acting on its own behalf. |
| `agent` | An AI agent that produced or assessed the content autonomously. Distinct from `tool` so that consumers can apply different trust policies to AI generated assertions. |

### Identity Identifier Types

| Label | Value | Description |
| --- | --- | --- |
| `email` | Email address, without the `mailto:` scheme. | Email address of the actor. |
| `url` | HTTPS URL | A web page or endpoint under the actor's control. |
| `did` | [DID][DID] | Decentralized identifier of the actor. |
| `spiffe` | [SPIFFE ID][SPIFFE] | SVID specifying the workload identity of a tool. |
| `purl` | Package URL | A software identifier specifying a sofrware piece as an identity. |

Note: OpenVEX does not validate the values.

### Identifier Keys

The keys of the `identifiers` map form a vocabulary. Bare keys, matching
`^[a-z][a-z0-9_]*$`, are reserved for the OpenVEX catalog in the table above.
Prefixed keys, of the form `prefix:type`, are identifier types defined by an
extension, following the [OpenVEX Extensions](EXTENSIONS.md) rules: the prefix
MUST be bound by an extension context declared in the document, and the
extension's specification defines the type and its value.

Consumers handle each key according to its shape:

| Key | Example | Meaning | Default behavior | Strict mode |
| --- | --- | --- | --- | --- |
| Bare key in the catalog | `email` | OpenVEX identifier type | Interpreted | Interpreted |
| Bare key not in the catalog | `badge` | Unknown identifier type | Preserved, SHOULD warn | Error |
| Prefixed key, prefix declared | `acme:badge` | Extension identifier type | Routed to the extension handler, or preserved when the consumer has none | Same |
| Prefixed key, prefix not declared | `whatever:value` | Undeclared extension data | Preserved, SHOULD warn | Error |

Unknown identifier types carry no VEX meaning, so ignoring them is harmless and
rejecting them by default would make documents written against a newer catalog
fail on older consumers. Consumers MAY offer a strict mode in which the two
warning cases are errors, for producers that want to catch mistakes before
publishing. The catalog is tied to the specification version named by the
document's `@context` IRI, so a strict consumer knows which catalog a document
was written against.

Because the map is an `@index` container in the JSON-LD context, its keys are
opaque index strings to JSON-LD processors and are not expanded. The vocabulary
above is therefore defined by this specification, not by the context. An
extension identifier type gains meaning in the graph only through the
extension's own definition.

### Identity References

Because OpenVEX documents are JSON-LD, an identity with an `@id` is a node in
the document's graph. An identity struct that carries only `@id` is a
reference to that node:

```json
"author": { "@id": "mailto:security@example.com" }
```

The referenced node MAY be fully described elsewhere, in the same document or
in another JSON-LD document. OpenVEX does not require consumers to resolve
references, a consumer that does not is left with the IRI, which is itself a
valid identifier of the actor.

### Identities as an Extension Point

The identity struct is an extension point as defined in the
[OpenVEX Extensions](EXTENSIONS.md) specification. Extensions MAY attach data
to an identity, for example the certificate details of a Sigstore identity or
an organization's internal account identifier.

## Fields That Take an Identity

The following fields accept an identity. In OpenVEX v1 each of them takes
either a string or an identity struct.

| Field | Location | String form today |
| --- | --- | --- |
| author | Document | Identifier of the document author. |
| supplier | Statement | Supplier of the product or subcomponent. |
| tooling | Document | Tools or processes that generated the document. |

### String Form

The string form is retained for compatibility and MUST be accepted by all
consumers. A string is an opaque label. Consumers MUST NOT infer an identifier
type from the shape of the string: `security@example.com` in the string form
is not an `email` identifier, it is a label that just happens to look like one.

Producers of v1 documents SHOULD emit the identity struct. A producer that only
has an unstructured label available MAY emit the string form.

The two forms do not mix within one field. A field holds a string or an
identity struct, never a list and never both.

### Example

```json
{
  "@context": "https://openvex.dev/ns/v1",
  "@id": "https://openvex.dev/docs/example/vex-identity-0001",
  "author": {
    "@id": "mailto:security@example.com",
    "name": "Example Security Team",
    "type": "organization",
    "identifiers": {
      "email": "security@example.com",
      "oidc:issuer": "https://accounts.google.com",
      "oidc:subject": "security@example.com"
    }
  },
  "role": "Product Security",
  "timestamp": "2026-05-07T18:02:03Z",
  "version": 1,
  "tooling": {
    "name": "vexctl",
    "type": "tool",
    "identifiers": {
      "url": "https://github.com/openvex/vexctl"
    }
  },
  "statements": [
    {
      "vulnerability": {
        "name": "CVE-2026-0001"
      },
      "products": [
        {
          "@id": "pkg:deb/debian/curl@7.50.3-1?arch=i386&distro=jessie"
        }
      ],
      "supplier": {
        "@id": "https://www.debian.org/",
        "name": "Debian",
        "type": "organization"
      },
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path"
    }
  ]
}
```

The `role` field stays at the document level next to `author`. It describes
the author's role with respect to this document, not a property of the
identity, and the same identity can hold different roles in different
documents.

## JSON-LD Context

The v1 context defines the identity terms in a property-scoped context on each
field that takes an idnetity, so that the same keys mean the same thing under
`author`, `supplier` and `tooling`. The term is left untyped at the top level:
a string value expands to a plain literal and an object value to a node. The
definition for `author`:

```json
{
  "author": {
    "@id": "openvex:author",
    "@context": {
      "name": {
        "@id": "openvex:identityName",
        "@type": "xsd:string"
      },
      "type": {
        "@id": "openvex:identityType",
        "@type": "openvex:identityType"
      },
      "identifiers": {
        "@id": "openvex:identityIdentifiers",
        "@container": "@index"
      }
    }
  }
}
```

`supplier` and `tooling` carry the same scoped context.

## JSON Schema

The v1 schema defines the identity struct once and references it from each
field that takes an identity:

```json
{
  "$defs": {
    "identity": {
      "type": "object",
      "properties": {
        "@id": {
          "type": "string",
          "format": "iri",
          "description": "IRI identifying the actor globally."
        },
        "name": {
          "type": "string",
          "description": "Human readable name of the actor."
        },
        "type": {
          "type": "string",
          "enum": ["person", "organization", "tool", "ai_agent"],
          "description": "The kind of actor."
        },
        "identifiers": {
          "type": "object",
          "minProperties": 1,
          "additionalProperties": { "type": "string" },
          "description": "Map of identifiers of the actor in external systems."
        }
      },
      "anyOf": [
        { "required": ["@id"] },
        { "required": ["name"] },
        { "required": ["identifiers"] }
      ],
      "additionalProperties": false
    }
  },
  "properties": {
    "author": {
      "oneOf": [
        { "type": "string" },
        { "$ref": "#/$defs/identity" }
      ],
      "description": "The author of the VEX document, as a label or an identity."
    }
  }
}
```

When the extensions mechanism is adopted, the identity definition admits
prefixed extension fields like every other extension point.

## Compatibility

- Every document valid today remains valid under v1. The string form is kept
  in all three fields.
- Documents that use the identity struct require a v1 consumer. They declare
  the v1 context IRI, which tells older consumers that they are looking at a
  newer format. go-vex already selects a parser from the context version to
  read older documents and can keep doing so.
- An identity struct is a different JSON shape, not an overloaded string, so a
  consumer never needs to guess whether a value is a label or an identifier.

## Revisions

| Date | Revision |
| --- | --- |
| 2026-10-29 | First draft. |

[DID]: https://www.w3.org/TR/did-core/
[IRI]: https://www.ietf.org/rfc/rfc3987.txt
[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119
[Sigstore]: https://www.sigstore.dev/
[SPIFFE]: https://spiffe.io/docs/latest/spiffe-about/spiffe-concepts/#spiffe-id
