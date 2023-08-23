# Attesting OpenVEX Documents

## What is an Attestation?

An attestation is an assertion made about a piece of software. There are many
kinds of attestations in use today such as provenance attestation defined by
SLSA or those asserting to the results of vulnerability scans.

OpenVEX was conceived to be able to be embedded in
[in-toto attestations](https://github.com/in-toto/attestation). The format defined
by the in-toto project is composed of a number of subjects (the pieces of
software the attestation is talking about) and a predicate that defines what is
being said about the subjects.

[DIAGRAM]

Here is an example of an empty attestation

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "",
  "subject": [],
  "predicate": {}
}
```

## Embedding and Inheritance

OpenVEX documents are designed to be embeddable in other formats. This is not a
unique feature of OpenVEX: the VEX minimum elements define the notion of an
"encapsulating format", a document that contains the VEX document and its
statements. VEX also defines an inheritance model where the required data to
complete VEX metadata cascades down from the encapsulating format to the
document, to the statement. This allows VEX to leverage the capabilities of the
encapsulating formats while defining a compatibility flow among implementations.

OpenVEX documents do not require an encapsulating document. Nevertheless, they
were designed to be embeddable and they can be used as in-toto predicates. This
lets software authors assert VEX data about a piece of software.

When embedding OpenVEX in attestations, the only field of data that "cascades"
is the VEX statement's `product`, or `subject` in in-toto lingo.

### The VEX Product and the Attestation's Subject

In VEX, all statements apply to one or more products. A "product" in VEX is a
loose term meaning any piece of software that can be listed in an SBOM. For a
statement to be valid, it needs to have one or more statements. Here's an example
of a VEX statement:

```json
    {
      "vulnerability": "CVE-2014-123456",
      "products": [
        "pkg:apk/distro/git@2.39.0-r1?arch=armv7",
        "pkg:apk/distro/git@2.39.0-r1?arch=x86_64"
      ],
      "status": "fixed"
    }
```

In the previous example, the statement specifies two packages of git (for armv7 and x86_64).

Attestations define their subjects natively. Following the VEX inheritance model
the subjects in an attestation containing a VEX document will cascade down and
become the VEX "product" of any statements that don't specify a subject.

Here is an example of an attestation with the same packages as subjects. Note that
the predicate type is set to the OpenVEX context (the predicate contents have been
removed for clarity):

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://openvex.dev/ns",
  "subject": [
    {
      "name": "pkg:apk/distro/git@2.39.0-r1?arch=armv7",
      "digest": {
        "sha256": "74634d9736a45ca9f6e1187e783492199e020f4a5c19d0b1abc2b604f894ac99"
      },
    },
    {
      "name": "pkg:apk/distro/git@2.39.0-r1?arch=x86_64",
      "digest": {
        "sha256": "6bd98fe56e4d91439343d123d98522005874957ea1cb6075e75544d7753bd8d7"
      },
    }
  ],
  "predicate": {
    // ...
  }
}

```

When embedding OpenVEX inside an attestation, the subjects SHOULD move from the
VEX statement product to the attestation subjects. This makes the attestation usable
in systems that already know how to process them while still keeping the VEX metadata
valid via the inheritance model. This is the complete attestation with the
embedded OpenVEX document:

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "text/vex",
  "subject": [
    {
      "name": "pkg:apk/distro/git@2.39.0-r1?arch=armv7",
      "digest": {
        "sha256": "74634d9736a45ca9f6e1187e783492199e020f4a5c19d0b1abc2b604f894ac99"
      },
    },
    {
      "name": "pkg:apk/distro/git@2.39.0-r1?arch=x86_64",
      "digest": {
        "sha256": "6bd98fe56e4d91439343d123d98522005874957ea1cb6075e75544d7753bd8d7"
      },
    }
  ],
  "predicate": {
    "@context": "https://openvex.dev/ns",
    "@id": "https://openvex.dev/docs/example/vex-9fb3463de1b57",
    "author": "Wolfi J Inkinson",
    "role": "Security Researcher",
    "timestamp": "2023-01-08T18:02:03.647787998-06:00",
    "version": "1",
    "statements": [
        {
            "vulnerability": "CVE-2023-12345",
            "status": "fixed"
        }
    ]
  }
}
```

Note in the finished example how the products in the statement have moved
toward the attestation's subject section. This example assumes that the
subjects' digests can be computed externally.

The product entries MAY remain in the VEX statement. In that case, they MUST
be repeated and matched in the attestation subject section. An attestation SHOULD
remain complete when composed with an OpenVEX predicate.

## Handling Product/Subject Granularity

An attestation's predicate is a singleton. It is a set of exactly one predicate
that applies to any number of subjects. VEX, on the other hand, defines a document
model that can host any number of statements, possibly with different subjects:

```json
"statements": [
    {
      "vulnerability": "CVE-2014-123456",
      "products": [
        "pkg:apk/distro/git@2.39.0-r1?arch=armv7"
      ],
      "status": "fixed"
    },
    {
      "vulnerability": "CVE-2014-123456",
      "products": [
        "pkg:apk/distro/git@2.39.0-r1?arch=x86_64"
      ],
      "status": "under_investigation"
    },
]
```

The nature of the data models implies that an attestation can only refer to
VEX statements that contain one or more of the `subject` entries in their product
section. To attest the example above, an attestation can use any of the following
subject structs:

```json
    "subject": {
        "pkg:apk/distro/git@2.39.0-r1?arch=armv7"
    }
```

```json
    "subject": {
        "pkg:apk/distro/git@2.39.0-r1?arch=x86_64"
    }
```

```json
    subject: {
        "pkg:apk/distro/git@2.39.0-r1?arch=armv7",
        "pkg:apk/distro/git@2.39.0-r1?arch=x86_64"
    }
```

When an identifier is listed in the subject section, it signals any processor
to look for data about it in the predicate. When looking at the VEX statements,
the following rules define how statements are to be considered:

1. Any VEX statements that don't define products are considered to be attested.
2. Any VEX statements listing products but not having the attestation's subjects
in the product list are to be ignored.
3. Any VEX statements including one of the attestation's subjects in its `product`
section are to be considered only for that identifier and others that match.
4. If a VEX statement lists one of the attestation's subjects in the product list
but not another, it MUST be considered for the former but not for the latter.

## Digital Signatures

Attestations are meant to be digitally signed. While the signature envelope is
not a part of the attestation or OpenVEX specifications, it should be noted that
VEX recommends that the document `author` _SHOULD be cryptographically associated
with the signature of the VEX document_. Signing an attestation SHOULD follow this
convention and sign the attestation when possible using the same identity
expressed in the author field. Since statements can originate from third parties
exploring the same product, this may not be possible in all circumstances.

An identity signing an attestation containing VEX statements from third parties
implies that the signer trusts those statements and has decided to include them
in the VEX impact history.
