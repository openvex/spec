# OpenVEX Specification v0.0.0

## Overview

OpenVEX is an implementation of Vulnerability Exploitability eXchange (VEX)
designed to be lightweight, and embeddable while meeting all requirements of
a valid VEX implementation as defined in the [Minimum Requirements for Vulnerability
Exploitability eXchange (VEX)](http://example.com) document published on XXX
by the VEX working group coordinated by the [Cybersecurity & Infrastructure
Security Agency](https://www.cisa.gov/) (CISA).


## The VEX Statement

VEX centers on the notion of a _statement_. In short, a statement can be defined
as an assertion intersecting product, a vulnerability, and an impact status:

```
   statement = product(s)             + vulnerability              + status
               │                        │                            │
               └ The software product   └ Typically a CVE related    └ One of the impact
                 we are talking about     to one of the product's      statuses as identified
                                          components                   by the VEX working group.
```

The `product` is a piece of software that can be correlated to an entry in an
SBOM (see [Product](#Product) below). `vulnerability` is the ID of a security 
vulnerability as understood by scanners, which can be looked up in a vulnerability
tracking system. `status` is one of the impact status labels defined by VEX
(see [Status](#Status)).

Another key part of VEX is time. It matters _when_ statements are made. VEX is
designed to be a sequence of statements, each overriding, but also enriching 
the previous ones with new information. Each statement has a timestamp
associated with it, either exlicitly in the markup or derived from containint
structures (see [Inheritance Flow](#Inheritance Flow)).

## VEX Documents

A VEX document is a data structure grouping one or more VEX statements.
Documents also have timestamps, which may cascade down to statements (see 
[Inheritance Flow](#Inheritance Flow)). Documents can also be versioned.

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
described in [RFC2119](https://www.ietf.org/rfc/rfc2119.txt).

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
The subcomponents SHOULD also be software identifiers and they SHOULD also be
listed in the product SBOM. subcomponents will most often be one or more of the
product's dependencies.

### Document

A VEX document consists of two parts: The document metadata and a collection
of statements. Some fields in the document metadata are required. 

OpenVEX documents are serialized in json-ld structs. File encoding MUST be UTF8.

Here is a sample of a minimal OpenVEX document:

```json
{
  "@context": "https://openvex.dev/ns",
  "@id": "https://openvex.dev/docs/example/vex-9fb3463de1b57",
  "author": "Wolfi J Inkinson",
  "role": "Document Creator",
  "timestamp": "2023-01-08T18:02:03.647787998-06:00",
  "version": "1",
  "statements": [
    {
      "vulnerability": "CVE-2023-12345",
      "products": [
        "pkg:apk/wolfi/git@2.39.0-r1?arch=armv7",
        "pkg:apk/wolfi/git@2.39.0-r1?arch=x86_64"
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
| @context | ✓ | The URL linking to the OpenVEX context definition. Fixed to `https://openvex.dev/ns`. | 
| @id | ✓ | The IRI identifying the VEX document.  |
| author | ✓ | Author is the identifier for the author of the VEX statement. Ideally, a common name, may be a URI. `author` can be an individual or organization. The author identity SHOULD be cryptographically associated with the signature of the VEX  statement or document or transport. |
| role | ✓ | role describes the role of the document author.  | 
| timestamp | ✓ | Timestamp defines the time at which the document was issued. | 
| version | ✓ | Version is the document version. It must be incremented when any content within the VEX document changes,  including any VEX statements included within the VEX document. |
| tooling | ✕ | Tooling expresses how the VEX document and contained VEX statements were generated. It's optional. It may specify tools or automated processes used in the document or statement generation. |
| supplier | ✕ | An optional field specifying who is providing the VEX document. |

### Statement

A statement is an assertion made by the document's author about the impact
a vulnerability has on one or more software "products". The statement has
three key components that are valid at a point in time: `status`, a `vulnerability`,
and the `product` to which these apply (see diagram above).

A statement in an OpenVEX document looks like the following snippet:

```json
  "statements": [
    {
      "vulnerability": "CVE-2023-12345",
      "products": [
        "pkg:apk/wolfi/git@2.39.0-r1?arch=armv7",
        "pkg:apk/wolfi/git@2.39.0-r1?arch=x86_64"
      ],
      "status": "fixed"
    }
  ]
```

#### Statement Fields

The following table lists the fields of the OpenVEX statement struct.

| Field | Required | Description |
| --- | --- | --- |
| vulnerability | ✓ | vulnerability SHOULD use existing and well known identifiers. For example: [CVE](https://cve.mitre.org/), [OSV](https://osv.dev/), (GHSA)[https://github.com/advisories], a supplier's vulnerability tracking system such as [RHSA](https://access.redhat.com/security/security-updates/#/) or a propietary system. It is expected that vulnerability identification systems are external to and maintained separately from VEX.<br>vulnerability MAY be URIs or URLs.<br>vulnerability  MAY be arbitrary and MAY be created by the VEX statement `author`.
| vuln_description | ✕ | Optional free-form text describing the vulnerability | 
| timestamp | ✕ | Timestamp is the time at which the information expressed in the Statement was known to be true. Cascades down from the document, see [Inheritance](#Inheritance). |
| products | ✕ | Product identifiers that the statement applies to. Any software identifier can be used and SHOULD be traceable to a described item in an SBOM. The use of [Package URLs](https://github.com/package-url/purl-spec) (purls) is recommended. While a product identifier is required to have a complete statement, this field is optional as it can cascade down from the encapsulating document, see [Inheritance](#Inheritance). |
| subcomponents | ✕ | Identifiers of components where the vulnerability originates. While the statement asserts about the impact on the software product, listing `subcomponents` let scanners find identifiers to match their findings. |
| status | ✓ | A VEX statement MUST provide the status of the vulnerabilities with respect to the products and components listed in the statement. `status` MUST be one of the labels defined by VEX (see [Status](#Status)), some of which have further options and requirements. | 
| status_notes | ✕ | A statement MAY convey information about how `status` was determined and MAY reference other VEX information. |
| justification | ✓/✕ | For statements conveying a `not_affected` status, a VEX statement MUST include either a status justification or an impact_statement informing why the product is not affected by the vulnerability. Justifications are fixed labels defined by VEX. See [Status Justifications](#Status Justifications) below for valid values. |
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
      "vulnerability": "CVE-2023-12345",
      "products": [
        "pkg:apk/wolfi/product@1.23.0-r1?arch=armv7",
      ],
      "status": "not_affected",
      "justification": "component_not_present",
      "impact_statement": "The vulnerable code was removed with a custom patch"
    }

```

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
[Status Justifications](status-doc) document on July 2022.


| Label | Description |
| --- | --- | 
| `component_not_present` | The product is not affected by the vulnerability because the component is not included. The status justification may be used to preemptively inform product users who are seeking to understand a vulnerability that is widespread, receiving a lot of attention, or is in similar products.  |
| `vulnerable_code_not_present` | The vulnerable component is included in artifact, but the vulnerable code is not present. Typically, this case occurs when source code is configured or built in a way that excluded the vulnerable code. |
| `vulnerable_code_not_in_execute_path` | The vulnerable code (likely in `subcomponents`) can not be executed as it is used by the product.<br><br>Typically, this case occurs when the product includes the vulnerable `subcomponent` but does not call or use the vulnerable code. |
| `vulnerable_code_cannot_be_controlled_by_adversary` | The vulnerable code cannot be controlled by an attacker to exploit the vulnerability.<br><br> This justification could  be difficult to prove conclusively. | 
| `inline_mitigations_already_exist` | The product includes built-in protections or features that prevent exploitation of the vulnerability. These built-in protections cannot be subverted by the attacker and cannot be configured or disabled by the user. These mitigations completely prevent exploitation based on known attack vectors.<br><br>This justification could be difficult to prove conclusively. History is littered with examples of mitigation bypasses, typically involving minor modifications of existing exploit code.

## Data Inheritance

VEX statements can inherit values from their document and/or, when embedded or 
incorporated into another format, from its [encapsulating document](#encaspu).

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
  "@context": "https://openvex.dev/ns",
  "@id": "https://openvex.dev/docs/example/vex-9fb3463de1b57",
  "author": "Wolfi J Inkinson",
  "role": "Document Creator",
  "timestamp": "2023-01-08T18:02:03-06:00",
  "version": "1",
  "statements": [
    {
      "vulnerability": "CVE-2023-12345",
      "products": [
        "pkg:apk/wolfi/git@2.39.0-r1?arch=armv7",
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
  "@context": "https://openvex.dev/ns",
  "@id": "https://openvex.dev/docs/example/vex-84822c4e5028c",
  "author": "Wolfi J Inkinson",
  "role": "Document Creator",
  "timestamp": "2023-01-09T09:08:42-06:00",
  "version": "1",
  "statements": [
    {
      "timestamp": "2023-01-08T18:02:03-06:00",
      "vulnerability": "CVE-2023-12345",
      "products": [
        "pkg:apk/wolfi/git@2.39.0-r1?arch=armv7",
      ],
      "status": "under_investigation"
    },
    {
      "vulnerability": "CVE-2023-12345",
      "products": [
        "pkg:apk/wolfi/git@2.39.0-r1?arch=armv7",
      ],
      "status": "fixed"
    },
  ]
}
```

## OpenVEX and JSON-LD

OpenVEX documents express data that is by nature interlinked. Documents and are
designed to be understood by [JSON-LD](https://www.w3.org/TR/json-ld11/) parsers,
this lets them reference resources expressed in other json-ld formats such as
[SPDX 3](https://github.com/spdx/spdx-3-model). 

### VEX Extensions

To make VEX documents JSON-LD compatible, OpenVEX extends the VEX minimum
requirements in the the following two ways:

1. OpenVEX extends the document identifier required by VEX to make the strings
compatible with the Internationalized Resource Identifier (IRI) specification
(see [RFC3987](https://www.rfc-editor.org/rfc/rfc3987)). 

2. Addition of the `@context` field at the document level. The additional field is
not required by VEX but it is added to make the documents parseable by json-ld
processors. 

### Public IRI Namespaces

As all documents are required to be identified by an IRI, open vex defines a 
public namespace that can be used by documents. Users of OpenVEX MAY choose to
use the shared namespace.

The shared namespace is defined under the openvex.dev domain name:

`    https://openvex.dev/docs/[name]    `

Users can start issuing IRIs for their documents by appending a IRI valid string
to the shared namespace:

`    https://openvex.dev/docs/[myproject]    `

There are two reserved shared namespaces with special meanings:

- `public` this is a public shared name where anybody that needs a valid IRI can
issue identifiers. Only recommended for demos or experiments where name collisions
don't matter.
- `example` a namespace for documentation, demos or other uses where no systems
are expected to run.

Please note that initially, OpenVEX does not provide a registry of namespaces or
hosting or redirection of IRIs. 

For more information check the OpenVEX [JSON-LD](JSON-LD.md) document and the
W3C's [JSON-LD reommendation](https://www.w3.org/TR/json-ld11/).

## Example

To illustrate how OpenVEX can specify a document switching off a false positive,
let's look at an example. According to the
[Spring Blog](https://spring.io/blog/2021/12/10/log4j2-vulnerability-and-spring-boot),
the included log4j library in Spring Boot 2.6.0 is within the versions affected by
the [log4shell vulnerability](https://nvd.nist.gov/vuln/detail/CVE-2021-44228).
In the post, however the project maintainers explain that it is not exploitable 
as shipped and they provide some details and guidance to users. 

To capture Spring's advise in an OpenVEX document and fend off any false positives,
the project could issue an OpenVEX document as follows:

```json
{
  "@context": "https://openvex.dev/ns",
  "@id": "https://openvex.dev/docs/public/vex-2e67563e128250cbcb3e98930df948dd053e43271d70dc50cfa22d57e03fe96f",
  "author": "Spring Builds <spring-builds@users.noreply.github.com>",
  "role": "Project Release Bot",
  "timestamp": "2023-01-16T19:07:16.853479631-06:00",
  "version": "1",
  "statements": [
    {
      "vulnerability": "CVE-2021-44228",
      "products": [
        "pkg:maven/org.springframework.boot/spring-boot@2.6.0"
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

## Revisions 

| Date | Revision |
| --- | --- | 
| 2023-01-08 | First Draft of the OpenVEX Specification |
| 2023-01-16 | Updated specx draft to reflect initial review |
| 2023-01-16 | Added JSON-LD and namespace section |
| 2023-01-16 | Add example section |


## Sources

status-doc: https://www.cisa.gov/sites/default/files/publications/VEX_Status_Justification_Jun22.pdf
