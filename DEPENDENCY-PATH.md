# OpenVEX Dependency Path

**Status:** Draft.<br>
**Target:** OpenVEX v1.<br>
**Author:** Adolfo García Veytia

> [!NOTE]
> This document is written to be merged into the OpenVEX specification as part
> of the product data structure section. Until then it lives here as a
> standalone draft.

## Overview

A VEX statement names a product, a vulnerability and the subcomponent the
vulnerability lives in. When the same subcomponent is included in a product
more than once, through different dependencies, the statement cannot tell the
inclusions apart. One route may expose the vulnerable code while another does
not, yet OpenVEX today can only speak about the subcomponent as a whole.

This document adds a `dependency_path` field to subcomponents. It records the
chain of dependencies through which the subcomponent reaches the product, and
makes the statement apply only to inclusions that follow that chain.

The design follows how knowledge of a dependency tree is distributed. A
software author knows which libraries their product uses directly. The deeper
the chain, the less the author knows and the more it changes as the supply
chain evolves. The path is therefore read from the product down, may stop at
any depth, and lets an author say exactly as much as they know: "this
vulnerability does not affect me when the subcomponent arrives through this
dependency", with the corollary that nothing is said about other routes.

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, MAY and OPTIONAL in
this document are to be interpreted as described in [RFC 2119].

## Definitions

- **Dependency chain:** The ordered sequence of components through which a
  subcomponent is included in a product, starting at a direct dependency of
  the product and ending at the subcomponent.
- **Observed chain:** A dependency chain determined by a consumer for an
  occurrence of a subcomponent in a product, from a source such as a
  dependency graph or a reachability analysis.
- **Path-attributed finding:** A vulnerability finding that carries the
  observed chain through which the vulnerable component is reached.
- **Path-agnostic finding:** A vulnerability finding that names a vulnerable
  component without a chain.

## Component Types

The specification describes products and subcomponents as sharing an abstract
`component` type. The JSON schema names its definitions the other way around.
v1 aligns them. Three types are defined, each adding one field to the previous:

| Type | Fields | Used by |
| --- | --- | --- |
| `component` | `@id`, `identifiers`, `hashes` | Elements of a dependency path |
| `subcomponent` | component fields plus `dependency_path` | Entries of `subcomponents` |
| `product` | component fields plus `subcomponents` | Entries of `products` |

Subcomponents keep every field they have today and gain `dependency_path`.
Products are unchanged. The elements of a dependency path are plain
components: they identify a dependency and carry no subcomponents and no path
of their own.

## The `dependency_path` Field

| Field | Required | Description |
| --- | --- | --- |
| dependency_path | ✕ | Ordered list of `component` structs describing the dependency chain through which the subcomponent is included in the product, read from the product down. |

The list is ordered from the product down to the subcomponent:

- The first element MUST be a direct dependency of the product.
- Each following element MUST be a direct dependency of the element before it.
- The list MUST NOT be empty.

The list MAY stop before reaching the subcomponent. It then describes a
contiguous prefix of the full chain, and everything between its last element
and the subcomponent is unconstrained. The list MUST NOT skip levels: an
author who knows a direct dependency and a deeper one but not what lies
between them states the direct dependency only.

The list MAY end with the subcomponent itself. The subcomponent is the final
node of every chain, so a path that ends with it describes the whole chain,
and a one-element path naming the subcomponent states that it is a direct
dependency of the product. An `@id` reference is sufficient for this element.

Listing the subcomponent is a claim about the bottom of the chain, which is
where an author's knowledge is weakest. Authors SHOULD do so only when they
know the chain ends there, and stop earlier otherwise.

Elements are matched like any other component, using the same identifier and
hash rules as products and subcomponents.

An element identifies a dependency, not necessarily a version of it. A
versionless purl matches any version, as it does elsewhere, and is the usual
form for a path element: the versions of intermediate dependencies change far
more often than the chain itself, and pinning them ties the statement to a
moment in time for no gain. Authors SHOULD add a version or hashes to an
element only when the chain differs between versions of that dependency.

### Example

The product below includes log4j-core twice. The Spring Boot logging starter
pulls it in through the slf4j binding, where the product never passes
attacker-controlled data to the logger. A legacy reporting module pulls it in
separately and does. The two inclusions get different statements.

```json
{
  "@context": "https://openvex.dev/ns/v1",
  "@id": "https://openvex.dev/docs/example/vex-dependency-path-0001",
  "author": "Example Security Team",
  "timestamp": "2026-05-07T18:02:03Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "name": "CVE-2021-44228"
      },
      "products": [
        {
          "@id": "pkg:maven/com.example/shop-api@4.2.0",
          "subcomponents": [
            {
              "identifiers": {
                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
              },
              "hashes": {
                "sha-256": "402fa523b96591d4450ace90e32d9f779fcfd938903e1c5bf9d3701860b8f856"
              },
              "dependency_path": [
                {
                  "identifiers": {
                    "purl": "pkg:maven/org.springframework.boot/spring-boot-starter-logging"
                  }
                },
                {
                  "@id": "pkg:maven/org.apache.logging.log4j/log4j-slf4j-impl"
                },
                {
                  "@id": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
                }
              ]
            }
          ]
        }
      ],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "impact_statement": "The logging starter wires log4j-core as the slf4j backend only. No user controlled input reaches a logger through this path."
    },
    {
      "vulnerability": {
        "name": "CVE-2021-44228"
      },
      "products": [
        {
          "@id": "pkg:maven/com.example/shop-api@4.2.0",
          "subcomponents": [
            {
              "identifiers": {
                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
              },
              "dependency_path": [
                {
                  "identifiers": {
                    "purl": "pkg:maven/com.example/legacy-reports@1.3.0"
                  }
                }
              ]
            }
          ]
        }
      ],
      "status": "affected",
      "action_statement": "Upgrade legacy-reports to 1.4.0, which drops the log4j dependency."
    }
  ]
}
```

The first statement lists the whole chain: the author knows the starter pulls
in the slf4j binding and that the binding depends on log4j-core directly, so
the path ends with the subcomponent. The intermediates carry no version, since
the chain is the same across their releases. The second statement stops at
the direct dependency and pins its version: the author knows the
vulnerability arrives through legacy-reports 1.3.0, says nothing about how
legacy-reports includes it, and the next release drops the dependency.

The dependency tree of the product, with the two paths the statements
describe:

```text
shop-api@4.2.0
│
├── spring-boot-starter-logging          ─┐
│   └── log4j-slf4j-impl                  ├─ statement 1 path: listed down
│       └── log4j-core@2.14.1  (CVE)     ─┘  to the subcomponent, not_affected
│
└── legacy-reports@1.3.0                 ─── statement 2 path: stops here,
    └── (not stated by the author)           anything below matches, affected
        └── log4j-core@2.14.1  (CVE)
```

A consumer that observes log4j-core reached through the starter and the slf4j
binding matches the first path exactly. One that observes it reached through
legacy-reports, by whatever intermediate steps, matches the second.

## Matching

A statement whose subcomponent carries a `dependency_path` applies to an
occurrence of that subcomponent in the product only when the observed chain
for the occurrence starts with the stated path, element by element from the
product down, with each element matched as a component. What follows the
stated elements is unconstrained. The observed chain ends with the
subcomponent itself, so a path that ends with the subcomponent matches only
when the stated elements are the entire chain.

A consumer that cannot determine an observed chain for an occurrence MUST NOT
apply a statement that carries a `dependency_path` to it. The statement is
neither matched nor ignored (see [Resolving Findings](#resolving-findings)).

Observed chains are an input to the consumer. This specification does not
prescribe where they come from. Typical sources are dependency graphs, such as
SBOM relationships, lockfiles and package manager output, and reachability
analyzers that report the chain through which vulnerable code is reached.
Consumers match path elements at the component level and are responsible for
mapping finer grained chains, such as package level traces, onto components.

A statement whose subcomponent carries no `dependency_path` matches every
occurrence of the subcomponent, as today.

## Resolving Findings

A vulnerability finding is resolved by a VEX document when the statements that
apply to it determine its status. With dependency paths, how a finding is
resolved depends on whether it carries a chain.

| Finding | Observed chains | Resolved when |
| --- | --- | --- |
| Path-attributed | The chain the finding carries | A statement applies to that chain. |
| Path-agnostic, chain data available | Every chain from the product to the component | Every chain has an applying statement. |
| Path-agnostic, no chain data | None | Never. The consumer reports the statement as present but not evaluated. |

A path-agnostic finding names a component, not a route to it, and therefore
stands for every route at once. When the consumer can enumerate the chains:

- If any chain matches a statement with status `affected`, the finding is
  affected.
- If every chain matches a statement with status `not_affected` or `fixed`,
  the finding is resolved with that status.
- Otherwise the finding remains open. Consumers SHOULD report which chains lack
  a statement.

Consumers MUST distinguish three outcomes in their results: no statement
applies, a statement was applied, and a statement with a `dependency_path`
is present but could not be evaluated. The third outcome tells the user that
the gap is in the available chain data, not in the VEX document.

## Authoring Guidance

- State the path to the depth you know. A single direct dependency is a
  valid and useful path.
- A path-scoped statement speaks only for its path. To address every inclusion
  of a subcomponent, issue a statement per path or a statement without a path.
- Where inclusions differ in impact, issue separate statements with separate
  paths, as in the example. Consumers report the paths that remain affected,
  which is the information needed to fix them.

## JSON-LD Context

The v1 context defines `dependency_path` as an ordered list. Arrays are
unordered sets in JSON-LD unless declared otherwise, and the order of the path
carries meaning, so the term uses a list container:

```json
{
  "dependency_path": {
    "@id": "openvex:dependencyPath",
    "@container": "@list"
  }
}
```

The elements are components, so the existing `identifiers` and `hashes` term
definitions apply inside them unchanged.

## JSON Schema

The v1 schema defines the three component types. `component` holds the
identification fields, `subcomponent` adds `dependency_path`, and `product`
adds `subcomponents`:

```json
{
  "$defs": {
    "component": {
      "type": "object",
      "properties": {
        "@id": {
          "type": "string",
          "format": "iri",
          "description": "Optional IRI identifying the component to make it externally referenceable."
        },
        "identifiers": {
          "$ref": "#/$defs/identifiers",
          "description": "A map of software identifiers where the key is the type and the value the identifier."
        },
        "hashes": {
          "$ref": "#/$defs/hashes",
          "description": "Map of cryptographic hashes of the component."
        }
      },
      "anyOf": [
        { "required": ["@id"] },
        { "required": ["identifiers"] }
      ],
      "additionalProperties": false
    },
    "subcomponent": {
      "type": "object",
      "properties": {
        "@id": { "$ref": "#/$defs/component/properties/@id" },
        "identifiers": { "$ref": "#/$defs/component/properties/identifiers" },
        "hashes": { "$ref": "#/$defs/component/properties/hashes" },
        "dependency_path": {
          "type": "array",
          "description": "Ordered list of components describing the dependency chain through which the subcomponent is included in the product, from the product down. The list may end with the subcomponent itself to describe the whole chain.",
          "minItems": 1,
          "items": { "$ref": "#/$defs/component" }
        }
      },
      "anyOf": [
        { "required": ["@id"] },
        { "required": ["identifiers"] }
      ],
      "additionalProperties": false
    },
    "product": {
      "type": "object",
      "properties": {
        "@id": { "$ref": "#/$defs/component/properties/@id" },
        "identifiers": { "$ref": "#/$defs/component/properties/identifiers" },
        "hashes": { "$ref": "#/$defs/component/properties/hashes" },
        "subcomponents": {
          "type": "array",
          "uniqueItems": true,
          "description": "List of subcomponent structs describing the subcomponents subject of the VEX statement.",
          "items": { "$ref": "#/$defs/subcomponent" }
        }
      },
      "anyOf": [
        { "required": ["@id"] },
        { "required": ["identifiers"] }
      ],
      "additionalProperties": false
    }
  }
}
```

`products` entries reference `product`. The current schema's `component`
definition, which carries `subcomponents`, is renamed to `product`, and its
`subcomponent` definition becomes `component`. Documents are unaffected by the
rename. When the extensions mechanism is adopted, all three types admit
prefixed extension fields.

## Compatibility

- The field is additive. Every document valid today remains valid under v1.
- Documents that use `dependency_path` declare the v1 context IRI. Consumers
  that do not implement this field MUST NOT apply statements that carry it, and
  consumers built for earlier versions reject v1 documents by their context
  version, which keeps the failure closed.
- Because an unknown chain never matches, adding a path to a statement can only
  narrow where it applies. A path-scoped `not_affected` statement **never**
  suppresses a finding on a consumer that cannot verify the path.

## Open Questions

- Matching granularity when a distribution package bundles several source
  packages and chain data is reported at the source package level.
- Whether consumers should offer a relaxed mode that treats a path as satisfied
  when its components are merely present in the product. It fits inventory
  only scanners but cannot prove the subcomponent arrived through them, so if
  offered it must be opt-in and its results marked as heuristic.

## Revisions

| Date | Revision |
| --- | --- |
| 2026-10-30 | First draft. |

[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119
