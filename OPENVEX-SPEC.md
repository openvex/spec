# OpenVEX Specification v0.2.0

## Overview

OpenVEX is an implementation of Vulnerability Exploitability eXchange (VEX)
designed to be lightweight, and embeddable while meeting all requirements of
a valid VEX implementation as defined in the [Minimum Requirements for VEX]
document published on April 2023 as defined by the VEX Working Group coordinated
by the [Cybersecurity & Infrastructure Security Agency][CISA] (CISA).

## The VEX Statement

VEX centers on the notion of a _statement_. In short, a statement can be defined
as an assertion intersecting product, a vulnerability, and an impact status:

```text
   statement = product(s)             + vulnerability              + status
               │                        │                            │
               └ The software product   └ Typically a CVE related    └ One of the impact
                 we are talking about     to one of the product's      statuses as identified
                                          components                   by the VEX working group.
```

The `product` is a piece of software that can be correlated to an entry in an
SBOM (see [Product](#product) below). `vulnerability` is the ID of a security
vulnerability as understood by scanners, which can be looked up in a vulnerability
tracking system. `status` is one of the impact status labels defined by VEX
(see [Status](#status)).

Another key part of VEX is time. It matters _when_ statements are made. VEX is
designed to be a sequence of statements, each overriding, but also enriching
the previous ones with new information. Each statement has a timestamp
associated with it, either explicitly in the markup or derived from containing
structures (see [Inheritance Flow](#inheritance-flow)).

## VEX Documents

A VEX document is a data structure grouping one or more VEX statements.
Documents also have timestamps, which may cascade down to statements (see
[Inheritance Flow](#inheritance-flow)). Documents can also be versioned.

### A Sample Scenario

As an example, consider the following evolution of a hypothetical impact analysis:

1. A software author becomes aware of a new CVE related to their product.
Immediately, the author starts to check if it affects them.
2. The investigation determines the product is affected.
3. To protect their users, the author mitigates the CVE impact via a patch or
other method before the vulnerable component issues a patch.

Without VEX data, users scanning the author's software will simply get
a third party alert with no details on how the status is evolving. Most critically,
when the product is patched (in #3), the alert becomes a false positive.

To inform consumers downstream of the vulnerability evolution, the author can
issue a VEX document (in #1) when the CVE is published to let their users
know it is under investigation. In #2, when the product is known to be affected,
the author can ship a new VEX document, stating the product is affected and
possibly some additional advice, like temporary mitigation instructions. Finally
when the product is patched, its SBOM can be complemented with a new VEX document
informing it is no longer affected by the CVE. Scanners could consume this
document and stop alerting about the CVE as it no longer impacts the product.

## OpenVEX Specification

### Definitions

The following definitions are used throughout this document.

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" are to be interpreted as
described in [RFC2119].

#### Document

A data structure that groups together one or more VEX statements. A document
MUST define a timestamp to express when it was issued.

#### Encapsulating Document

While OpenVEX defines a self-sustaining document format, VEX data can often be
found embedded or incorporated in other formats, examples of this include
in-toto attestations or CSAF and CycloneDX documents. "Encapsulating document"
refers to these formats that can contain VEX data.

#### Product

A logical unit representing a piece of software. The concept is intentionally
broad to allow for a wide variety of use cases but generally speaking, anything
that can be described in a Software Bill of Materials (SBOM) can be thought of
as a product.

#### Status

The known relationship a vulnerability has to a software product. The status
expresses if the product is impacted by the vulnerability or not, if the authors
are investigating it, or if it has already been fixed.

#### Vulnerability

A cataloged defect in a software product. Documents SHOULD use global, well-known
identifying schemas. For internal identifying schemes, the only requirement
for a vulnerability to be listed in a VEX document is that it needs to have an ID
string to address it. Public identifiers (such as CVE IDs) are the most
common case, but private internal identifiers can be used if they are
understood by all participants of the supply chain where the VEX metadata is
expected to flow.

#### Subcomponent

Any components possibly included in the product where the vulnerability originates.
The subcomponents SHOULD also list software identifiers and they SHOULD also be
listed in the product SBOM. `subcomponents` will most often be one or more of the
product's dependencies.

### Document

A VEX document consists of two parts: The document metadata and a collection
of statements. Some fields in the document metadata are required.

OpenVEX documents are serialized in json-ld structs. File encoding MUST be UTF8.

Here is a sample of a minimal OpenVEX document:

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://openvex.dev/docs/example/vex-9fb3463de1b57",
  "author": "Wolfi J Inkinson",
  "role": "Document Creator",
  "timestamp": "2023-01-08T18:02:03.647787998-06:00",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "name": "CVE-2023-12345"
      },
      "products": [
        {"@id": "pkg:apk/wolfi/git@2.39.0-r1?arch=armv7"},
        {"@id": "pkg:apk/wolfi/git@2.39.0-r1?arch=x86_64"}
      ],
      "status": "fixed"
    }
  ]
}

```

#### Document Struct Fields

The following table lists the fields in the document struct

| Field | Required | Description |
| --- | --- | --- |
| @context | ✓ | The URL linking to the OpenVEX context definition. The URL is structured as https://openvex.dev/ns/v[version], where [version] represents the specific version number, such as v0.2.0. If the version is omitted, it defaults to v0.0.1. |
| @id | ✓ | The IRI identifying the VEX document. |
| author | ✓ | Author is the identifier for the author of the VEX statement. This field should ideally be a machine readable identifier such as an IRI, email address, etc. `author` MUST be an individual or organization. `author` identity SHOULD be cryptographically associated with the signature of the VEX document or other exchange mechanism. |
| role | ✕ | role describes the role of the document author.  |
| timestamp | ✓ | Timestamp defines the time at which the document was issued. |
| last_updated | ✕ | Date of last modification to the document. |
| version | ✓ | Version is the document version. It must be incremented when any content within the VEX document changes, including any VEX statements included within the VEX document. |
| tooling | ✕ | Tooling expresses how the VEX document and contained VEX statements were generated. It may specify tools or automated processes used in the document or statement generation. |

### Statement

A statement is an assertion made by the document's author about the impact
a vulnerability has on one or more software "products". The statement has
three key components that are valid at a point in time: `status`, a `vulnerability`,
and the `product` to which these apply (see diagram above).

A statement in an OpenVEX document looks like the following snippet:

```json
  "statements": [
    {
      "vulnerability": {
        "name": "CVE-2023-12345"
      },
      "products": [
        {"@id": "pkg:apk/wolfi/git@2.39.0-r1?arch=armv7"},
        {"@id": "pkg:apk/wolfi/git@2.39.0-r1?arch=x86_64"}
      ],
      "status": "fixed"
    }
  ]
```

#### Statement Fields

The following table lists the fields of the OpenVEX statement struct.

| Field | Required | Description |
| --- | --- | --- |
| @id | ✕ | Optional IRI identifying the statement to make it externally referenceable. |
| version | ✕ | Optional integer representing the statement's version number. Defaults to zero, required when incremented. |
| vulnerability | ✓ | A struct identifying the vulnerability. See the [Vulnerability Data Structure](#vulnerability-data-structure) section below for the complete data structure reference. |
| timestamp | ✕ | Timestamp is the time at which the information expressed in the Statement was known to be true. Cascades down from the document, see [Inheritance](#inheritance-flow). |
| last_updated | ✕ | Timestamp when the statement was last updated. |
| products | ✕ | List of product structs that the statement applies to. See the [Product Data Structure](#product-data-structure) section below for the full description. While a product is required to have a complete statement, this field is optional as it can cascade down from the encapsulating document, see [Inheritance](#inheritance-flow). |
| status | ✓ | A VEX statement MUST provide the status of the vulnerabilities with respect to the products and components listed in the statement. `status` MUST be one of the labels defined by VEX (see [Status](#status-labels)), some of which have further options and requirements. |
| supplier | ✕ | Supplier of the product or subcomponent. |
| status_notes | ✕ | A statement MAY convey information about how `status` was determined and MAY reference other VEX information. |
| justification | ✓/✕ | For statements conveying a `not_affected` status, a VEX statement MUST include either a status justification or an impact_statement informing why the product is not affected by the vulnerability. Justifications are fixed labels defined by VEX. See [Status Justifications](#status-justifications) below for valid values. |
| impact_statement | ✓/✕ | For statements conveying a `not_affected` status, a VEX statement MUST include either a status justification or an impact_statement informing why the product is not affected by the vulnerability. An impact statement is a free form text containing a description of why the vulnerability cannot be exploited. This field is not intended to be machine readable so its use is highly discouraged for automated systems. |
| action_statement | ✕ | For a statement with "affected" status, a VEX statement MUST include a statement that SHOULD describe actions to remediate or mitigate the vulnerability. |
| action_statement_timestamp | ✕ | The timestamp when the action statement was issued. |

##### Note on `justification` and `impact_statement`

The Minimal Requirements for VEX document states that a `not_affected` statement
MUST provide either a machine readable `justification` label or a free form
text `impact_statement`. OpenVEX defines both required fields but highly discourages
the use of the impact statement textual form as it breaks VEX automation and
interoperability.

The recommended pattern from OpenVEX is that issuers SHOULD use the machine
readable justification labels and optionally enrich the statement with an
`impact_statement`:

```json
    {
      "vulnerability": {
        "name": "CVE-2023-12345",
      }
      "products": [
        {"@id": "pkg:apk/wolfi/product@1.23.0-r1?arch=armv7"}
      ],
      "status": "not_affected",
      "justification": "component_not_present",
      "impact_statement": "The vulnerable code was removed with a custom patch"
    }

```

### Product Data Structure

The subject of an VEX statement is the _product_, a piece of software that MUST be
addressable via one of the mechanisms offered by OpenVEX. The spec provides an
expressive `product` struct with fields to address the product using identifiers,
hashes. Note that all mechanisms to address the product are optional but a
valid statement MUST identify a product to be valid.

The optional `@id` field takes an [IRI][IRI] to make the product referenceable
inside the document and addressable externally. As Package URLs are valid IRIs,
the `@id` can take a purl as a value.

The product field should list as many software identifiers as possible to
help VEX processors when matching the product. The use of
[Package URLs][purl-spec] (purls) is recommended.

The product and its subcomponents fields share an abstract type called
`Component` that defines the fields that can be used to identify them.
The only difference in `product` is the nested `subcomponents` field.

#### Example Product Struct

```json
{
  "@id": "pkg:apk/wolfi/product@1.23.0-r1?arch=armv7",
  "identifiers": {
    "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.4",
    "cpe23": "cpe:2.3:a:apache:log4j:2.4:-:*:*:*:*:*:*",
    "cpe22": "cpe:/a:apache:log4j:2.4:-",
  },
  "hashes": {
    "sha-256": "402fa523b96591d4450ace90e32d9f779fcfd938903e1c5bf9d3701860b8f856",
    "sha-512": "d2eb65b083923d90cf55111c598f81d3d9c66f4457dfd173f01a6b7306f3b222541be42a35fe47191a9ca00e017533e8c07ca192bd22954e125557c72d2a3178"
  },
  "subcomponents": []
}

```

#### Component Fields

These fields are shared by both the `product` and `subcomponent` structs:

| Field | Required | Description |
| --- | --- | --- |
| @id | ✕ | Optional [IRI][IRI] identifying the component to make it externally referenceable. |
| identifiers | ✕ | A map of software identifiers where the key is the type and the value the identifier. OpenVEX favors the use of purl but others are recognized (see the Identifiers Labels table below) |
| hashes | ✕ | Map of cryptographic hashes of the component. The key is the algorithm name based on the [Hash Function Textual Names][iana-hash-function-names] from IANA. See [Hash Names Table](#appendix-a-hash-names-table) for the full supported list. |

The `product` struct uses the above listed fields but has a list of subcomponents,
each itself a `component` subclass:

| Field | Required | Description |
| --- | --- | --- |
| subcomponents | ✕ | List of `component` structs describing the subcomponents subject of the VEX statement. |

### Vulnerability Data Structure

The vulnerability field in an OpenVEX statement takes the value of a struct that
has the capability to enumerate the vulnerability name and other aliases that may
be used to track it in different databases and systems.

As with the product field, the vulnerability has an optional "@id" field that
takes an IRI to make the field referenceable in the document and linkable from
other linked data resources.

#### Example Vulnerability Struct

```json
{
  "vulnerability": {
    "@id": "https://nvd.nist.gov/vuln/detail/CVE-2019-17571",
    "name": "CVE-2019-17571",
    "description": "The product deserializes untrusted data without sufficiently verifying that the resulting data will be valid.",
    "aliases": [
        "GHSA-2qrg-x229-3v8q",
        "openSUSE-SU-2020:0051-1",
        "SNYK-RHEL7-LOG4J-1472071",
        "DSA-4686-1",
        "USN-4495",
        "DLA-2065-1",
    ],
  }
}
```

#### Vulnerability Struct Fields

The only required field in the vulnerability field is `name`, the main identifier
of the vulnerability. Note that it is not an error to include the identifier used
in the `name` field in the list of aliases.

| Field | Required | Description |
| --- | --- | --- |
| @id | ✕ | An Internationalized Resource Identifier (IRI) identifying the struct. Used to reference and link the vulnerability data. |
| name | ✓ | A string with the main identifier used to name the vulnerability. |
| description | ✕ | Optional free form text describing the vulnerability. |
| aliases | x | A list of strings enumerating other names under which the vulnerability may be known. |

### Status Labels

Status labels inform the impact of a vulnerability in the products listed
in a statement. Security tooling such as vulnerability scanners consuming OpenVEX
documents can key on the status labels to alter their behavior when a vulnerable
component is detected. Security dashboards can provide users and auditors
with contextual data about the evolution of the vulnerability impact.

| Label | Description |
| --- | --- |
| `not_affected` | No remediation is required regarding this vulnerability. A `not_affected` status required the addition of a `justification` to the statement. |
| `affected` | Actions are recommended to remediate or address this vulnerability. |
| `fixed` | These product versions contain a fix for the vulnerability. |
| `under_investigation` | It is not yet known whether these product versions are affected by the vulnerability. Updates should be provided in further VEX documents as knowledge evolves. |

Any of these key data points are required to form a valid statement but
they are not necessarily required to be defined in the statement's data struct.
Consider the following scenarios:

### Status Justifications

When assessing risk, consumers of a `not_affected` software product can know
why the vulnerability is not affected by reading the justification label
associated with the VEX statement. These labels are predefined and machine-readable
to enable automated uses such as deployment policies. The current label catalog
was defined by the VEX Working Group and published in the
[Status Justifications] document on July 2022.

| Label | Description |
| --- | --- |
| `component_not_present` | The product is not affected by the vulnerability because the component is not included. The status justification may be used to preemptively inform product users who are seeking to understand a vulnerability that is widespread, receiving a lot of attention, or is in similar products.  |
| `vulnerable_code_not_present` | The vulnerable component is included in artifact, but the vulnerable code is not present. Typically, this case occurs when source code is configured or built in a way that excluded the vulnerable code. |
| `vulnerable_code_not_in_execute_path` | The vulnerable code (likely in `subcomponents`) can not be executed as it is used by the product.<br><br>Typically, this case occurs when the product includes the vulnerable `subcomponent` but does not call or use the vulnerable code. |
| `vulnerable_code_cannot_be_controlled_by_adversary` | The vulnerable code cannot be controlled by an attacker to exploit the vulnerability.<br><br> This justification could  be difficult to prove conclusively. |
| `inline_mitigations_already_exist` | The product includes built-in protections or features that prevent exploitation of the vulnerability. These built-in protections cannot be subverted by the attacker and cannot be configured or disabled by the user. These mitigations completely prevent exploitation based on known attack vectors.<br><br>This justification could be difficult to prove conclusively. History is littered with examples of mitigation bypasses, typically involving minor modifications of existing exploit code.

## Data Inheritance

VEX statements can inherit values from their document and/or, when embedded or
incorporated into another format, from its [encapsulating document](#encapsulating-document).

A valid VEX statement needs to have four key data points which act as
the grammatical parts of a sentence:

- One or more products. These are the direct objects of the statement.
- A status. The status can be thought of as the verb.
- A vulnerability. The vulnerability is the indirect object.
- A timestamp. This is the time complement of the statement. A statement is useless without a timestamp as it cannot be related to others talking about the same subject.

In OpenVEX, timestamps and product identifiers can be defined outside the
statements to avoid defining redundant info or to leverage external features.

__Note:__  While this specification lists these data fields as optional in the
statement data struct, the data MUST be defined to have complete statements. A
document with incomplete statements is not valid.

#### Data Economy

A document defining multiple statements, all issued at the same time can be
made less verbose by just inferring the statement timestamps from the date the
document was issued.

#### Encapsulating Format

VEX is designed to be encapsulated in other document formats which may have
redundant features or be better at expressing the required data points. For
example, an in-toto attestation can contain a VEX document in its predicate
while its subject section lists the software the VEX data applies to.

Another example is CSAF. The format defines a sophisticated tree that
can specify complex groups and families of products. In this case, product
identification can be left blank in the VEX statement and leverage CSAF's
powerful product tree features.

### Inheritance Flow

As mentioned data specifying a statement's product or timestamp can originate
outside. As the data cascades, more specific elements can override the data
defined in more general ones. The following two phrases define how the
inheritance flow works:

#### Timestamps

A timestamp in a `statement` entry overrides a timestamp defined at the
document level which in turn overrides timestamps defined on the encapsulating
document.

#### Product ID

A product identifier defined in a `statement` entry overrides any product
identification data defined on the encapsulating document.

### Updating Statements with Inherited Data

When updating a document with statements with data implied via inheritance,
the integrity of the untouched statements MUST be preserved. In the following
example, the sole statement has its timestamp data derived from the document:

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://openvex.dev/docs/example/vex-9fb3463de1b57",
  "author": "Wolfi J Inkinson",
  "role": "Document Creator",
  "timestamp": "2023-01-08T18:02:03-06:00",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "name": "CVE-2023-12345"
      },
      "products": [
        {"@id": "pkg:apk/wolfi/git@2.39.0-r1?arch=armv7"}
      ],
      "status": "under_investigation"
    }
  ]
}
```

When adding a second statement, the document date needs to be updated, but to
preserve the integrity of the original statement we need to keep the original
document timestamp. The newly added statement can inherit the document's date
to avoid duplication:

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://openvex.dev/docs/example/vex-84822c4e5028c",
  "author": "Wolfi J Inkinson",
  "role": "Document Creator",
  "timestamp": "2023-01-09T09:08:42-06:00",
  "version": 1,
  "statements": [
    {
      "timestamp": "2023-01-08T18:02:03-06:00",
      "vulnerability": {
        "name": "CVE-2023-12345"
      },
      "products": [
        {"@id": "pkg:apk/wolfi/git@2.39.0-r1?arch=armv7"},
      ],
      "status": "under_investigation"
    },
    {
      "vulnerability": {
        "name": "CVE-2023-12345"
      },
      "products": [
        {"@id": "pkg:apk/wolfi/git@2.39.0-r1?arch=armv7"}
      ],
      "status": "fixed"
    },
  ]
}
```

## OpenVEX and JSON-LD

OpenVEX documents express data that is by nature interlinked. Documents and are
designed to be understood by [JSON-LD][JSON-LD] parsers,
this lets them reference resources expressed in other json-ld formats such as
[SPDX 3][SPDX3].

### VEX Extensions

To make VEX documents JSON-LD compatible, OpenVEX extends the VEX minimum
requirements in the the following two ways:

1. OpenVEX extends the document identifier required by VEX to make the strings
compatible with the Internationalized Resource Identifier (IRI) specification
(see [RFC3987]).

2. Addition of the `@context` field at the document level. The additional field is
not required by VEX but it is added to make the documents parseable by json-ld
processors.

### Public IRI Namespaces

As all documents are required to be identified by an IRI, OpenVEX defines a
public namespace that can be used by documents. Users of OpenVEX MAY choose to
use the shared namespace.

The shared namespace is defined under the openvex.dev domain name:

`https://openvex.dev/docs/[name]`

Users can start issuing IRIs for their documents by appending a IRI valid string
to the shared namespace:

`https://openvex.dev/docs/[myproject]`

There are two reserved shared namespaces with special meanings:

- `public` this is a public shared name where anybody that needs a valid IRI can
issue identifiers. Only recommended for demos or experiments where name collisions
do not matter.
- `example` a namespace for documentation, demos or other uses where no systems
are expected to run.

Please note that initially, OpenVEX does not provide a registry of namespaces or
hosting or redirection of IRIs.

For more information check the OpenVEX [JSON-LD](JSON-LD.md) document and the
W3C's [JSON-LD recommendation][JSON-LD].

## Example

To illustrate how OpenVEX can specify a document switching off a false positive,
let's look at an example. According to the
[Spring Blog][log4j-spring-boot],
the included log4j library in Spring Boot 2.6.0 is within the versions affected by
the [log4shell vulnerability][log4shell-vulnerability].
In the post, however the project maintainers explain that it is not exploitable
as shipped and they provide some details and guidance to users.

To capture Spring's advise in an OpenVEX document and fend off any false positives,
the project could issue an OpenVEX document as follows:

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://openvex.dev/docs/public/vex-2e67563e128250cbcb3e98930df948dd053e43271d70dc50cfa22d57e03fe96f",
  "author": "Spring Builds <spring-builds@users.noreply.github.com>",
  "role": "Project Release Bot",
  "timestamp": "2023-01-16T19:07:16.853479631-06:00",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "@id": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        "name": "CVE-2021-44228",
        "description": "Remote code injection in Log4j",
        "aliases": [
          "GHSA-jfh8-c2jp-5v3q"
        ]
      },
      "products": [
        {
          "@id": "pkg:maven/org.springframework.boot/spring-boot@2.6.0-M3",
          "identifiers": {
            "purl": "pkg:maven/org.springframework.boot/spring-boot@2.6.0-M3",
          }
          "hashes":{
            "sha-256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
          }
        }
      ],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path"
      "impact_statement": "Spring Boot users are only affected by this vulnerability if they have switched the default logging system to Log4J2. The log4j-to-slf4j and log4j-api jars that we include in spring-boot-starter-logging cannot be exploited on their own. Only applications using log4j-core and including user input in log messages are vulnerable.",
    }
  ]
}
```

VEX-enabled security scanners could use the vex document to turn off the security
alert and dashboards could present users with the official guidance from the project.

## Appendix A: Hash Names Table

The following list of hash names can be used as keys in the `hashes` field of the
product field. These labels follow and extend the
[Hash Function Textual Names][iana-hash-function-names]
document from IANA.

| Hash Label |
| --- |
| md5 |
| sha1 |
| sha-256 |
| sha-384 |
| sha-512 |
| sha3-224 |
| sha3-256 |
| sha3-384 |
| sha3-512 |
| blake2s-256 |
| blake2b-256 |
| blake2b-512 |

## Appendix B: Software Identifier Types Table

The following labels can be used as keys when enumerating software identifiers
in the product data structure.

| Type Label | Identifier type |
| --- | --- |
| purl | [Package URL][purl-spec] |
| cpe22 | [Common Platform Enumeration v2.2][CPE-2.2] |
| cpe23 | [Common Platform Enumeration v2.3][CPE-2.3] |

## Revisions

| Date | Revision |
| --- | --- |
| 2023-07-18 | Added hash and identifier label catalog tables |
| 2023-07-18 | Updated spec to reflect changes in [OPEV-0015: Expansion of the Vulnerability Field][OPEV-0015] |
| 2023-07-18 | Updated spec to reflect changes in [OPEV-0014: Expansion of the VEX Product Field][OPEV-0014] |
| 2023-07-18 | Bumped version of the spec to v0.0.2 after update to meet the VEX-WG doc. |
| 2023-06-01 | Removed supplier from the document level (following VEX-WG doc). |
| 2023-05-29 | Specification updated to reflect the published [Minimum Requirements for VEX] document. |
| 2023-01-08 | First Draft of the OpenVEX Specification. |
| 2023-01-16 | Updated spec draft to reflect initial review. |
| 2023-01-16 | Added JSON-LD and namespace section. |
| 2023-01-16 | Add example section. |
| 2023-05-29 | Added missing fields to match the VEX-WG's [Minimum Requirements for VEX] document. |

## Sources

- Vulnerability Exploitability eXchange (VEX) - [Status Justifications]
- [Minimum Requirements for VEX] document, published by CISA.

[CISA]: https://www.cisa.gov/
[CPE-2.2]: https://cpe.mitre.org/files/cpe-specification_2.2.pdf
[CPE-2.3]: https://csrc.nist.gov/pubs/ir/7695/final
[iana-hash-function-names]: https://www.iana.org/assignments/named-information/named-information.xhtml
[IRI]: https://www.ietf.org/rfc/rfc3987.txt
[JSON-LD]: https://www.w3.org/TR/json-ld11/
[log4j-spring-boot]: https://spring.io/blog/2021/12/10/log4j2-vulnerability-and-spring-boot
[log4shell-vulnerability]: https://nvd.nist.gov/vuln/detail/CVE-2021-44228
[Minimum Requirements for VEX]: https://www.cisa.gov/sites/default/files/2023-04/minimum-requirements-for-vex-508c.pdf
[OPEV-0014]: https://github.com/openvex/community/blob/main/enhancements/opev-0014.md
[OPEV-0015]: https://github.com/openvex/community/blob/main/enhancements/opev-0015.md
[purl-spec]: https://github.com/package-url/purl-spec
[RFC2119]: https://www.rfc-editor.org/rfc/rfc2119
[RFC3987]: https://www.rfc-editor.org/rfc/rfc3987
[SPDX3]: https://github.com/spdx/spdx-3-model
[Status Justifications]: https://www.cisa.gov/sites/default/files/publications/VEX_Status_Justification_Jun22.pdf
