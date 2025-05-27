# OpenVEX Specification

OpenVEX is an implementation of the
[Vulnerability Exploitability Exchange](https://www.ntia.gov/files/ntia/publications/vex_one-page_summary.pdf)
(VEX for short) that is designed to be minimal, compliant, interoperable, and
embeddable.
The specification is available in the [OPENVEX-SPEC.md](OPENVEX-SPEC.md) file of this repository.

**Note**: The OpenVEX specification is currently a draft. We don't anticipate large changes, but are open to them.

## Principles

OpenVEX is designed with the following principles in mind:

### Meet the requirements defined by the [CISA SBOM and VEX Efforts](https://www.cisa.gov/sbom).

We believe OpenVEX meets these requirements now, and will do our best to ensure it continues to meet them as requirements
change.

### SBOM Agnostic

We believe VEX is most useful when decoupled from specific SBOM formats.

Several SBOM formats include ways to express VEX (both within and outside of the SBOM), but we feel a single VEX format
can be used across any SBOM format.
Further, while we do anticipate VEX will primarily be used with SBOMs, VEX is useful without them.

### Minimal

OpenVEX is minimal.
The specification is primarily intended to serve the use cases outlined in the CISA VEX definition.

## About VEX

Vulnerability Exploitability eXchange is a vulnerability document designed to
complement a Software Bill of Materials (SBOM) that informs users of a software
product about the applicability of one or more vulnerability findings.

Security scanners will detect and flag components in software that have
been identified as being vulnerable. Often, software is not necessarily affected
as signaled by security scanners for many reasons such as: the vulnerable component may
have been already patched, may not be present, or may not be able to be executed. To turn off
false alerts like these, a scanner may consume VEX data from the software supplier.

The extreme transparency brought by SBOMs into how software is composed will
most likely increase the number of these kind of false positives, requiring an
automated solution to avoid an explosion in the false positive rate of security
scans. Hence VEX.

## OpenVEX is...

### A Specification

OpenVEX documents are minimal JSON-LD files that capture the minimal requirements
for VEX as defined by the VEX working group organized by CISA. The
[OpenVEX Specification](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md)
is owned and steered by the community.

### A Go Library

The project has a go library
([openvex/go-vex](https://github.com/openvex/go-vex)) that lets projects generate,
transform and consume OpenVEX files. It enables the ingestion of VEX metadata
expressed in other VEX implementations.

### A Set of Tools

Work is underway to create the tools software authors and consumers need to
handle VEX metadata. The current flagship project is
[`vexctl`](https://github.com/openvex/vexctl), a CLI to create, merge and
attest VEX documents.

## What Does an OpenVEX Document Look Like?

An OpenVEX document is composed of a JSON-LD structure that contains the
[document metadata](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md#vex-documents)
and one or more
[VEX statements](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md#the-vex-statement):

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
        "name": "CVE-2014-123456"
      },
      "products": [
        {"@id": "pkg:apk/distro/git@2.39.0-r1?arch=armv7"},
        {"@id": "pkg:apk/distro/git@2.39.0-r1?arch=x86_64"}
      ],
      "status": "fixed"
    }
  ]
}
```

Check out
[the OpenVEX specification](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md)
and our [examples repository](https://github.com/openvex/examples) for more
information and use cases.

## How can I check if my OpenVEX document is valid?

There is a [JSON Schema](https://github.com/openvex/spec/blob/main/openvex_json_schema.json) for the OpenVEX specification. You can use tools listed on https://json-schema.org/implementations to check the validity of your OpenVEX document.

## OpenVEX Roadmap

The OpenVEX specification is currently a draft.
We believe the specification is usable today, but will focus on implementation and adoption in the short term.
We can't be fully confident the specification works until it has been implemented by a wide range of users, tools
and systems.

We're hoping for a 1.0 release in 2023.

## Frequently Asked Questions

#### How does this compare to CSAF?

OpenVEX is designed to be more Lightweight, easy to be recorded in
[Sigstore](https://sigstore.dev), and embedded in [in-toto](https://in-toto.io/)
attestations. While CSAF has a rich mechanism to express product trees,
OpenVEX favors [package URLs](https://github.com/package-url/purl-spec) (purl)
as its software identifier of choice.

#### How does this compare to CycloneDX VEX?

OpenVEX aims to be SBOM format agnostic. While there are plans to have both
CycloneDX and SPDX VEX implementations, we feel that VEX metadata should be
kept separate from the SBOM.

On the implementation details, the CycloneDX VEX implementation defines a
different set of
[status](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md#status-labels) and
[justification](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md#status-justifications)
labels than those defined by the VEX Working Group. To match CDX VEX documents to the unified labels documents have to be translated, which is not ideal.

#### Does it work with SBOMs?

Yes, OpenVEX is designed to be SBOM format agnostic. It can reference software
described in both SPDX and CycloneDX Software Bills of Materials.

#### Why not use CSAF or CycloneDX?

When OpenVEX was released, both the CSAF and CycloneDX implementations of VEX
are missing a few pieces of the minimum elements of VEX. Nevertheless, OpenVEX
can be used along with CSAF and CycloneDX documents. The OpenVEX tooling can
generate a complete VEX impact history from files expressed in the other
implementations

#### Who is behind this project?

This project uses a community governance model defined in the [community repository](https://github.com/openvex/community).
Contributions are welcome!
