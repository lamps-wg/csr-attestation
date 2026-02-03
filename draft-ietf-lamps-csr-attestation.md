---
title: "Use of Remote Attestation with Certification Signing Requests"
abbrev: "Remote Attestation with CSRs"
category: std

docname: draft-ietf-lamps-csr-attestation-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
# area: AREA
# workgroup: WG Working Group
keyword:
 - PKI
 - PKCS#10
 - CRMF
 - Attestation
 - Certificate Signing Requests
venue:
#  group: LAMPS
#  type: Working Group
#  mail: spasm@ietf.org
#  arch: https://datatracker.ietf.org/wg/lamps/about/
  github: "lamps-wg/csr-attestation"
  latest: "https://lamps-wg.github.io/csr-attestation/draft-ietf-lamps-csr-attestation.html"

author:
  -
    ins: M. Ounsworth
    name: Mike Ounsworth
    org: Entrust Limited
    abbrev: Entrust
    street: 2500 Solandt Road – Suite 100
    city: Ottawa, Ontario
    country: Canada
    code: K2K 3G5
    email: mike.ounsworth@entrust.com
  -
    name: Hannes Tschofenig
    organization: Siemens
    country: Germany
    email: Hannes.Tschofenig@gmx.net
  -
    name: Henk Birkholz
    org: Fraunhofer SIT
    abbrev: Fraunhofer SIT
    email: henk.birkholz@sit.fraunhofer.de
    street: Rheinstrasse 75
    code: '64295'
    city: Darmstadt
    country: Germany
  -
    ins: M. Wiseman
    name: Monty Wiseman
    org:
    country: USA
    email: mwiseman32@acm.org
  -
    ins: N. Smith
    name: Ned Smith
    org:
    country: United States
    email: ned.smith.ietf@gmail.com

normative:
  RFC9334:
  RFC6268:
  RFC5912:
  RFC4211:
  RFC2986:
  RFC5280:

informative:
  RFC8126:
  RFC5226:
  I-D.ietf-rats-msg-wrap:
  I-D.bft-rats-kat:
  RFC7030:
  I-D.tschofenig-rats-psa-token:
  I-D.ffm-rats-cca-token:
  CSBR:
    author:
      org: CA/Browser Forum
    title: Baseline Requirements for Code-Signing Certificates, v.3.7
    date: February 28, 2024
    target: https://cabforum.org/uploads/Baseline-Requirements-for-the-Issuance-and-Management-of-Code-Signing.v3.7.pdf
  TCGDICE1.2:
    author:
      org: "Trusted Computing Group"
    title: "DICE Attestation Architecture"
    target: https://trustedcomputinggroup.org/wp-content/uploads/DICE-Attestation-Architecture-v1.2_pub.pdf
    date: April, 2025
  SampleData:
    title: "CSR Attestation Sample Data"
    target: https://github.com/lamps-wg/csr-attestation-examples

--- abstract

Certification Authorities (CAs) issuing certificates to Public Key Infrastructure (PKI) end entities may require a certificate signing request (CSR) to include additional verifiable information to confirm policy compliance. For example, a CA may require an end entity to demonstrate that the private key corresponding to a CSR's public key is secured by a hardware security module (HSM), is not exportable, etc. The process of generating, transmitting, and verifying  additional information required by the CA is called remote attestation. While work is currently underway to standardize various aspects of  remote attestation, a variety of proprietary mechanisms have been in use for years, particularly regarding protection of private keys.

This specification defines ASN.1 structures which may carry attestation data for PKCS#10 and Certificate
Request Message Format (CRMF) messages. Both standardized and proprietary attestation formats are supported by this specification.
--- middle

# Introduction

Certification Authorities (CAs) issuing certificates to PKI end entities MAY require a certificate signing request (CSR) to include verifiable attestations that contain claims regarding the platform used by the end entity to generate the key pair for which a certificate is sought and also contains claims of attributes of the key pair with respect to its protection, use and extractability. At the time of writing, the most pressing example of the need for remote attestation in certificate enrollment is the Code-Signing Baseline Requirements (CSBR) document maintained by the CA/Browser Forum [CSBR]. The [CSBR] requires compliant CAs to "ensure that a Subscriber's Private Key is generated, stored, and used in a secure environment that has controls to prevent theft or misuse". This requirement is a natural fit to enforce via remote attestation.

This specification defines an attribute and an extension that allow for conveyance of verifiable attestations in several Certificate Signing Request (CSR) formats, including PKCS#10 [RFC2986] or Certificate Request Message Format (CRMF) [RFC4211] messages. Given several standard and proprietary remote attestation technologies are in use, this specification is intended to be as technology-agnostic as is feasible with respect to implemented and future remote attestation technologies. This aligns with the fact that a CA may wish to provide support for a variety of types of devices but cannot dictate what format a device uses to represent attestations.  However, if a certificate requester does not include the number and types of attestations required by the CA, it is unlikely the requester will recieve the requested certificate.

While CSRs are defined using Abstract Syntax Notation One (ASN.1), attestations may be defined using any data description language, i.e., ASN.1 or Concise Data Description Language (CDDL), or represented using any type of encoding, including Distinguished Encoding Rules (DER), Concise Binary Object Representation (CBOR), JavaScript Object Notation (JSON). This specification RECOMMENDS that attestations that are not encoded using the Basic Encoding Rules (BER) or Distinguished Encoding Rules (DER) be wrapped in an ASN.1 OCTET STRING.

## Relationship to the IETF RATS Working Group

As noted, attestation-related technologies have existed for many years, albeit with no standard format and no standard means of conveying attestation information to a CA. This draft addresses the latter, and is equally applicable to standard and proprietary attestation formats. The IETF Remote Attestation Procedures (RATS) working group is addressing the former. In {{RFC9334}}, RATS defined vocabulary, architecture, and usage patterns related to the practice of generating and verifying attestations.

In its simplest topological model, attestations are generated by the certificate requester and verified by the CA/RA. Section 5 of {{RFC9334}} defines topological patterns that are more complex,
including the background check model and the passport model.  This
document may be applied to instantiating any of these topological
models for CSR processing, provided the required security
requirements specific to the context of certificate issuance are
satisfied.

The trust model defined in {{Section 7 of RFC9334}} identifies several roles that originate or forward attestations: the Attester; Endorser; and Verifier. Attestations, or Evidence per {{RFC9334}}, may be directed to an entity fulfilling one of these roles, including to an CA/RA acting as a Verifier. An CA/RA may also forward attestations to a Verifier for evaluation. Each attestation may contain one or more claims, including claims that may be required by an RA or CA. Attestations transmitted by these parties are defined in {{Section 8 of RFC9334}} as the "conceptual messages" Evidence, Endorsement, and Attestation Results. The structure defined in this specification may be used by any of the roles that originate attestations, and is equally applicable to these three conceptual messages.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document re-uses the terms defined in {{RFC9334}} related to remote
attestation. Readers of this document are assumed to be familiar with
the following terms defined in {{RFC9334}}: Evidence, Endorsement, Claim, Attestation Result (AR), Attester, Relying Party, and Verifier.
Per {{RFC9334}}, the CA/RA is the Relying Party with respect to remote attestation. This use of the term "relying party" differs from the traditional PKIX use of the term.
This specification uses CA/RA to refer to an {{RFC9334}} Relying Party, which may or may not include an integrated Verifier.

The term "Certification Request" message is defined in {{RFC2986}}.
Specifications, such as {{RFC7030}}, later introduced the term
"Certificate Signing Request (CSR)" to refer to the Certification
Request message. While the term "Certification Request"
would have been correct, the mistake was unnoticed. In the meanwhile
CSR is an abbreviation used beyond PKCS#10. Hence, it is equally
applicable to other protocols that use a different syntax and
even a different encoding, in particular this document also
considers messages in the Certificate Request Message Format (CRMF) {{RFC4211}}
to be "CSRs". In this document, the terms "CSR" and Certificate Request
message are used interchangeably.

The term "hardware security module (HSM)" is used generically to refer to the
combination of hardware and software designed to protect keys from unauthorized
access. Other commonly used terms include Secure Element, Trusted Platform Module, and Trusted Execution
Environment.

Since this document combines terminology from two domains, Remote Attestation (RATS) and X.509 PKI, it follows a naming convention to avoid ambiguity.
RATS terminology is written in uppercase (e.g., Verifier), while X.509/PKI terminology is written in lowercase (e.g., certification authority (CA)).
This distinction clarifies terms that exist in both domains; for instance, a Verifier refers to the RATS entity that processes Evidence, whereas a verifier refers to the PKI entity that validates certificates.
This convention is distinct from camel-case identifiers like "AttestationStatement", which denote ASN.1 types.

# Conveying attestations in CSRs {#sec-attestationAttr}

The focus of this specification is the conveyance of attestations to a CA/RA as part of a CSR.
The following sub-sections define formats to support this conveyance, an optional mechanism to limit support to specific attestation types at the ASN.1 level, and bindings to the attribute and extension mechanisms used in certificate managment protocols.

## AttestationStatement and AttestationBundle
The `AttestationStatement` structure (as shown in {{code-AttestationStatement}}) facilitates the representation of Evidence, Endorsements,
and Attestation Results generated by an Attester, Endorser, or Verifier for processing by a Verifer or Relying Party, such as verification by a CA/RA.

* The `type` field is an OBJECT IDENTIFIER that identifies the format of the `stmt` field.
* The `bindsPublicKey` field indicates whether the attestation in the `stmt` field is cryptographically bound to the public key included in the CSR.
* The `stmt` field contains the attestation for processing, constrained by the `type` field. Formats that are not defined using ASN.1 MUST define an ASN.1 wrapper for use with the `AttestationStatement` structure.
For example, a CBOR-encoded format may be defined as an OCTET STRING for `AttestationStatement` purposes, where the contents of the OCTET STRING are the CBOR-encoded data.
* The `attrs` field enables the inclusion of `Attribute` values that may inform the verification of the `stmt`. This specification does not define any `Attribute` instances, but does define an empty set of ATTRIBUTE `AttestAttrSet`.
* The `attrs` field, while not directly bound to the `type` of attestation, SHOULD generally contain at least the set of Attributes described the the document related to a specific ATTESTATION-STATEMENT declaration.  

~~~
ATTESTATION-STATEMENT ::= TYPE-IDENTIFIER

AttestationStatement ::= SEQUENCE {
   type   ATTESTATION-STATEMENT.&id({AttestationStatementSet}),
   bindsPublicKey BOOLEAN DEFAULT TRUE,
   stmt   ATTESTATION-STATEMENT.&Type({AttestationStatementSet}{@type}),
   attrs  Attributes OPTIONAL
}
~~~
{: #code-AttestationStatement title="Definition of AttestationStatement"}

In some cases, a CA may require CSRs to include a variety of claims, which may require the cooperation of more than one Attester.
Similarly, a CA/RA may outsource verification of claims from different Attesters to a single Verifier.
The `AttestationBundle` structure, {{code-AttestationBundle}}, facilitates the representation of one or more `AttestationStatement` structures along with an OPTIONAL collection of certificates that may be useful for certification path building and validation to verify each `AttestationStatement`. `AttestationBundle` is the structure included in a CSR attribute or extension.

~~~
AttestationBundle ::= SEQUENCE {
   attestations SEQUENCE SIZE (1..MAX) OF AttestationStatement,
   certs SEQUENCE SIZE (1..MAX) OF LimitedCertChoices OPTIONAL,
}
~~~
{: #code-AttestationBundle title="Definition of AttestationBundle"}

At least one element in the `attestations` field SHOULD contain an attestation that is cryptographically bound to the public key that is the subject of the CSR containing the `AttestationBundle`.

The `CertificateChoices` structure defined in {{RFC6268}}, and reproduced below along with `OtherCertificateFormat`, allows for carrying certificates in the default X.509 {{RFC5280}} format, or in other non-X.509 certificate formats. `CertificateChoices` MUST only contain certificate or other. In this context, `CertificateChoices` MUST NOT contain `extendedCertificate`, `v1AttrCert`, or `v2AttrCert`. Note that for non-ASN.1 certificate formats, the `CertificateChoices` MUST contain `other` with an `OTHER-CERT-FMT.Type` of `OCTET STRING` and data consistent with `OTHER-CERT-FMT.id`. `LimitedCertChoices` is defined to limit the available options to `certificate` and `other`.

~~~
   CertificateChoices ::= CHOICE {
     certificate Certificate,
     extendedCertificate [0] IMPLICIT ExtendedCertificate,
          -- Obsolete
     ...,
     [[3: v1AttrCert [1] IMPLICIT AttributeCertificateV1]],
          -- Obsolete
     [[4: v2AttrCert [2] IMPLICIT AttributeCertificateV2]],
     [[5: other      [3] IMPLICIT OtherCertificateFormat]] }
   OTHER-CERT-FMT ::= TYPE-IDENTIFIER

   OtherCertificateFormat ::= SEQUENCE {
     otherCertFormat OTHER-CERT-FMT.
             &id({SupportedCertFormats}),
     otherCert       OTHER-CERT-FMT.
             &Type({SupportedCertFormats}{@otherCertFormat})}

LimitedCertChoices ::= CertificateChoices (WITH COMPONENTS {\
                                                 certificate, other})
~~~

The `certs` field contains a set of certificates that
may be used to validate an `AttestationStatement`
contained in `attestations`. For each `AttestationStatement`, the set of certificates SHOULD contain
the certificate that contains the public key needed to directly validate the
`AttestationStatement`, unless the signing key is expected to be known to the Verifier or is embedded within the `AttestationStatement`. Additional certificates MAY be provided, for example, to chain the
attestation signer key back to a trust anchor. No specific order of the certificates in `certs` should be expected because certificates contained in `certs` may be needed to validate different `AttestationStatement` instances.

This specification places no restriction on mixing certificate types within the `certs` field. For example a non-X.509 attestation signer certificate MAY chain to a trust anchor via a chain of X.509 certificates. It is up to the Attester and its Verifier to agree on supported certificate formats.

## AttestationStatementSet
~~~
AttestationStatementSet ATTESTATION-STATEMENT ::= {
   ... -- None defined in this document --
}
~~~
{: #code-AttestationStatementSet title="Definition of AttestationStatementSet"}

The expression illustrated in {{code-AttestationStatementSet}} maps ASN.1 Types
for attestation statements to the OIDs
that identify them. These mappings are used to construct
or parse `AttestationStatement` objects that appear in an `AttestationBundle`. Attestation statements are typically
defined in other IETF standards, in standards produced by other standards bodies,
or as vendor proprietary formats along with corresponding OIDs that identify them.
`AttestationStatementSet` is left unconstrained in this document. However, implementers MAY
populate it with the formats that they wish to support.

## CSR Attribute and Extension

By definition, attributes within a PKCS#10 CSR are typed as ATTRIBUTE and within a CRMF CSR are typed as EXTENSION.

~~~
id-aa-attestations OBJECT IDENTIFIER ::= { id-aa 59 }

-- For PKCS#10
attr-attestations ATTRIBUTE ::= {
  TYPE AttestationBundle
  COUNTS MAX 1
  IDENTIFIED BY id-aa-attestation
}

-- For CRMF
ext-attestations EXTENSION ::= {
  SYNTAX AttestationBundle
  IDENTIFIED BY id-aa-attestation
}
~~~
{: #code-extensions title="Definitions of CSR attribute and extension"}

The Extension variant illustrated in {{code-extensions}} is intended only for use within CRMF CSRs and is NOT RECOMMENDED to be used within X.509 certificates due to the privacy implications of publishing information about the end entity's hardware environment.

Multiple different types of `AttestationStatement`(s) may be included within a single top-level `AttestationBundle`.  N.B.; there is no requirement in this document that the `AttestationBundle.attestations` field contain only one `AttestationStatement` of a given type.  For example, if a given type is a "wrapper" type containing the `CMW` structure REF NEEDED, multiple copies of a CMW-typed AttestationStatement may be included. 

Per {{RFC5280}} no more than one instance of a given type of Extension may be carried within an Extensions structure, so an Extensions structure MUST contain no more than one Extension of type `id-aa-attestation.

Per {{RFC2986}} `Attributes{}` is defined as a `SET OF Attribute{}`, so an Attributes structure carried within a PKCS#10 CSR MUST contain no more than one Attribute of type `id-aa-attestation`.

Finally, the `attr-attestation` ATTRIBUTE includes the  "COUNT MAX 1" constraint, so an Attribute of type `id-aa-attesatation` MUST contain exactly one copy of an `AttestationBundle`.

# IANA Considerations

IANA is requested to allocate a value
from the "SMI Security for PKIX Module Identifier" registry for the
included ASN.1 module, allocate a value from "SMI Security for
S/MIME Attributes" to identify two attributes defined within, and open a new registry.

##  Module Registration - SMI Security for PKIX Module Identifier

IANA is asked to register the following within the registry id-mod
SMI Security for PKIX Module Identifier (1.3.6.1.5.5.7.0).

-  Decimal: IANA Assigned - **Replace TBDMOD**
-  Description: CSR-ATTESTATION-2023 - id-mod-pkix-attest-01
-  References: This Document

##  Object Identifier Registrations - SMI Security for S/MIME Attributes

IANA is asked to register the following within the registry id-aa
SMI Security for S/MIME Attributes (1.2.840.113549.1.9.16.2).

- Attestation Statement
- Decimal: IANA Assigned - This was early-allocated as `59` so that we could generate the sample data.
- Description: id-aa-attestation
- References: This Document

## Attestation OID Registry

IANA is asked to create a registry that helps developers to find
OID/Attestation mappings that may be encountered in the wild, as well as
a link to their specification document and an indication as to whether the attestation is cryptographically bound to a public key.
This registry should follow the rules for
"Expert Review" as laid out in {{RFC5226}}.

This is an informational registry only, and may be used to lookup a given OID to find the specifications or contact person for a given ATTESTATION-STATEMENT declaration.  While a full specification is preferred, all that is required is a statement by the registering entity that owns a given OID tree that the registration has occurred.   The Designated Expert should verify the OID ownership, and may reviw any addtional documentation prior to approving the registration.

Each row includes an OID and ASN.1 type that could appear in an `ATTESTATION-STATEMENT` declaration, and references to find the specification or point of contact.

Registration requests should be formatted as per
the registration template below, and receive a three-week review period on
the [spasm] mailing list, with the advice of one or more Designated
Experts {{RFC8126}}.  

Registration requests sent to the mailing list for review should use
an appropriate subject (e.g., "Request to register attestation
attestation: example").

IANA must only accept registry updates from the Designated Experts
and should direct all requests for registration to the review mailing
list.

### Registration Template

The registry has the following columns:

- OID: The OID number, which has already been allocated. IANA does
not necessarily allocate this OID number.  There is no IANA OID allocation for this registry, but OIDs in other IANA registries may be appropriate for use in an ATTESTATION-STATEMENT declaraton.

- Name: The part of the declaration prior to the `ATTESTATION-STATEMENT` keyword. 

- Type: The ASN.1 type corresponding to the given OID.

- Description: Brief description of the use of the Attestation and the
registration of the OID.

- Reference(s): Either a reference to the registering entity, or a a reference to the document or documents that register
the OID and define the ASN.1 type for use with a specific attestation technology, preferably
including URIs that can be used to retrieve copies of the documents.
An indication of the relevant sections may also be included but is not
required.

Example:

Assuming the following ASN.1:

~~~
id-example-attest OBJECT IDENTIFIER ::= { 1 2 3 4 5 }

ExampleStruct ::= OCTET STRING

exampleAttest ATTESTATION-STATEMENT ::= { ExampleStruct IDENTIFIED BY id-example-attest}
~~~

The template would be:

- OID: 1.2.3.4.5
- Name: exampleAttest
- Type ExampleStruct
- Description:  This is an example template for registering ATTESTATATION-STATEMENT declarations
- Reference: Provided by example@example.com, no specification provided.

### Initial Registry Contents

None.

The current registry values can be retrieved from the IANA online website.

[spasm]: mailto:spasm@ietf.org

# Security Considerations

This document defines a structure to convey
attestations as additional information in CSRs, as well as an extension to convey that structure in the
Certification Request Message defined in {[RFC2986]} and an attribute to convey that structure in the
Certificate Request Message Format defined in {[RFC4211]}.
The CA/RA that receives the CSR may choose to verify the attestation(s) to determine if an issuance policy is met, or which of a suite of policies is satisfied. The CA/RA is also free to discard the additional information without processing. 

A CA which accepts or requires attestation(s) SHOULD document its requirements with its Certification Practice Statement(s).

The remainder of this section identifies security considerations that apply when the CA/RA chooses to verify the attestation as part of the evaluation of a CSR.

## Binding attestations to the CSR’s public key

Regardless of the topological model, the CA/RA is ultimately responsible for validating the binding between the public key and the attestation(s) in the CSR. For CAs issuing in conformance with the CA/Browser Forum’s Code Signing Baseline Requirements, this means verifying the attestation of HSM generation and protection is cryptographically bound to the public key in the CSR.

Multiple attestations from multiple sources, as envisioned in {{RFC9334}}, can introduce additional complications as shown in the following example.

### Binding Multiple Claims to a CSR

For example, a CA may have an issuance policy that requires key generation in an HSM on a company-owned platform in a known good state.
The CSR might contain three AttestationStatements originated by three different attesters:

1. an Evidence that a key pair was generated in an HSM;
2. an Endorsement that states a particular platform is company-owned; and
3. an Attestation Result stating a particular platform was in a known good state (e.g, up to date on patches, etc.).

While each of these attestations may be independently correct, the CA/RA is responsible for confirming the attestations apply in concert to the public key in the CSR. That is, the CA/RA must analyze the attestations to ensure that:

1. the attestation of HSM generation in AttestationStatement 1 applies to the public key in the CSR;
2. the attestation of company ownership in AttestationStatement 2 applies to the platform that contains the HSM; and
3. the attestation that a platform was in a known good state in AttestationStatement 3 applies to the platform that contains the HSM.

## Freshness

To avoid replay attacks, the CA/RA may choose to ignore attestations that are stale, or whose freshness cannot be determined. Mechanisms to address freshness and their application to the RATS topological models are discussed in {{RFC9334}}. Other mechanisms for determining freshness may be used as the CA/RA deems appropriate.

## Relationship of Attestations and Certificate Extensions

Attestations are intended as additional information in the issuance process, and may include sensitive information about the platform, such as hardware details or patch levels, or device ownership. It is NOT RECOMMENDED for a CA to copy attestations into the published certificate. CAs that choose to republish attestations in certificates SHOULD review the contents and delete any sensitive information.   

## Additional Security Considerations

In addition to the security considerations listed here, implementers should be familiar with the security considerations of the specifications on which this specification depends: PKCS#10 {{RFC2986}}, CRMF {{RFC4211}}, as well as general security concepts relating to remote attestation; many of these concepts are discussed in {{Section 6 of RFC9334}}, {{Section 7 of RFC9334}}, {{Section 9 of RFC9334}}, {{Section 11 of RFC9334}}, and {{Section 12 of RFC9334}}. Implementers should also be aware of any security considerations relating to the specific attestation formats being carried within the CSR.
 

--- back


# Examples

Examples and sample data will be collected in the "CSR Attestation Sample Data" GitHub repository {{SampleData}}.


# ASN.1 Module

~~~
{::include-fold CSR-ATTESTATION-2025.asn}
~~~

# Acknowledgments

This specification is the work of a design team created by the chairs of the
LAMPS working group. The following persons, in no specific order,
contributed to the work directly, participated in design team meetings, or provided review of the document.

Richard Kettlewell, Chris Trufan, Bruno Couillard,
Jean-Pierre Fiset, Sander Temme, Jethro Beekman, Zsolt Rózsahegyi, Ferenc
Pető, Mike Agrenius Kushner, Tomas Gustavsson, Dieter Bong, Christopher Meyer, Carl Wallace, Michael Richardson, Tomofumi Okubo, Olivier
Couillard, John Gray, Eric Amador, Darren Johnson, Herman Slatman, Tiru Reddy, James Hagborg, A.J. Stein, John Kemp, Daniel Migault and Russ Housley.

We would like to specifically thank Mike StJohns for his work on an earlier
version of this draft.

We would also like to specifically thank Giri Mandyam for providing the
appendix illustrating the confidential computing scenario, and to Corey
Bonnell for helping with the hackathon scripts to bundle it into a CSR.

Finally, we would like to thank Andreas Kretschmer, Hendrik Brockhaus,
David von Oheimb, and Thomas Fossati for their feedback based on implementation
experience.

