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
 - Evidence
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
    org: Beyond Identity
    country: USA
    email: monty.wiseman@beyondidentity.com
  -
    ins: N. Smith
    name: Ned Smith
    org: Intel Corporation
    country: United States
    email: ned.smith@intel.com

normative:
  RFC9334:
  RFC6268:
  RFC5912:
  RFC4211:
  RFC2986:
  ASN1-2002:
    author:
      org: ITU-T
    title: "ITU-T Recommendation X.680, X.681, X.682, and X.683"
    date: 2002

informative:
  RFC8126:
  I-D.ietf-rats-msg-wrap:
  I-D.bft-rats-kat:
  RFC7030:
  RFC8141:
  I-D.tschofenig-rats-psa-token:
  TPM20:
    author:
      org: Trusted Computing Group
    title: Trusted Platform Module Library Specification, Family 2.0
    target: https://trustedcomputinggroup.org/resource/tpm-library-specification/
  CSBR:
    author:
      org: CA/Browser Forum
    title: Baseline Requirements for Code-Signing Certificates, v.3.7
    date: February 28, 2024
    target: https://cabforum.org/uploads/Baseline-Requirements-for-the-Issuance-and-Management-of-Code-Signing.v3.7.pdf
  TCGOIDREG:
    author:
      org: "Trusted Computing Group"
    title: "TCG OID Registry landing page"
    target: https://trustedcomputinggroup.org/resource/tcg-oid-registry/
    date: October, 2024
  PKCS11:
    author:
      org: OASIS
    title: "PKCS #11 Cryptographic Token Interface Base Specification Version 2.40"
    date: 14 April 2015
    target: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/pkcs11-base-v2.40-os.html
  SampleData:
    title: "CSR Attestation Sample Data"
    target: https://github.com/lamps-wg/csr-attestation-examples

--- abstract

A PKI end entity requesting a certificate from a Certification Authority (CA) may wish to offer trustworthy claims about the platform generating the certification request and the environment associated with the corresponding private key, such as whether the private key resides on a hardware security module.

This specification defines an attribute and an extension that allow for conveyance of Evidence in Certificate Signing Requests (CSRs) such as PKCS#10 or Certificate Request Message Format (CRMF) payloads which provides an elegant and automatable mechanism for transporting Evidence to a Certification Authority.

Including Evidence along with a CSR can help to improve the assessment of the security posture for the private key, and can help the Certification Authority to assess whether it satisfies the requested certificate profile. These Evidence Claims can include information about the hardware component's manufacturer, the version of installed or running firmware, the version of software installed or running in layers above the firmware, or the presence of hardware components providing specific protection capabilities or shielded locations (e.g., to protect keys).


--- middle

# Introduction

When requesting a certificate from a Certification Authority (CA), a PKI end entity may wish to include Evidence of the security properties of its environments in which the private keys are stored in that request.
This Evidence can be appraised by authoritative entities, such as a Registration Authority (RA) or a CA, or associated trusted Verifiers as part of validating an incoming certificate request against given certificate policies. Regulatory bodies are beginning to require proof of hardware residency for certain classifications of cryptographic keys. At the time of writing, the most notable example is the Code-Signing Baseline Requirements {{CSBR}} document maintained by the CA/Browser Forum, which requires compliant CAs to "ensure that a Subscriber’s Private Key is generated, stored,
and used in a secure environment that has controls to prevent theft or misuse".

This specification defines an attribute and an extension that allow for conveyance of Evidence in Certificate Signing Requests (CSRs) such as PKCS#10 {{RFC2986}} or Certificate Request Message Format (CRMF) {{RFC4211}} payloads which provides an elegant and automatable mechanism for transporting Evidence to a Certification Authority and meeting requirements such as those in the CA/B Forum's {{CSBR}}.

As outlined in the RATS Architecture {{RFC9334}}, an Attester (typically
a device) produces a signed collection of Claims that constitute Evidence about its running environment(s).
While the term "attestation" is not defined in RFC 9334, it was later defined in {{?I-D.ietf-rats-tpm-based-network-device-attest}}, it refers to the activity of producing and appraising remote attestation Evidence.
A Relying Party may consult an Attestation Result produced by a Verifier that has appraised the Evidence in making policy decisions about the trustworthiness of the
Target Environment being assessed via appraisal of Evidence. {{architecture}} provides the basis to illustrate in this document how the various roles
in the RATS architecture map to a certificate requester and a CA/RA.


At the time of writing, several standard and several proprietary remote attestation technologies
are in use.
This specification thereby is intended to be as technology-agnostic as it is feasible with respect to implemented remote attestation technologies. Hence, this specification focuses on (1) the conveyance of Evidence via CSRs while making minimal assumptions about content or format of the transported Evidence and (2) the conveyance of sets of certificates used for validation of Evidence.
The certificates typically contain one or more certification paths
rooted in a device manufacturer trust anchor and the end-entity certificate being
on the device in question. The end-entity certificate is associated with key material that takes on the role of an Attestation Key and is used as Evidence originating from the Attester.

This document specifies a CSR Attribute (or Extension for Certificate Request Message Format (CRMF) CSRs) for carrying Evidence. Evidence can be placed into an EvidenceStatement along with an OID to identify its type and optionally a hint to the Relying Party about which Verifier (software package) will be capable of parsing it. A set of EvidenceStatements may be grouped together along with the set of CertificateChoices needed to validate them to form a EvidenceBundle. One or more EvidenceBundles may be placed into the id-aa-evidence CSR Attribute (or CRMF Extension).

A CSR may contain one or more Evidence payloads, for example Evidence
asserting the storage properties of a private key, Evidence
asserting firmware version and other general properties
of the device, or Evidence signed using different cryptographic
algorithms.

With these attributes, additional
information information is available to an RA or CA, which may be used
to decide whether to issue a certificate and what certificate profile
to apply. The scope of this document is, however,
limited to the conveyance of Evidence within CSR. The exact format of the
Evidence being conveyed is defined in various standard and proprietary
specifications.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document re-uses the terms defined in {{RFC9334}} related to remote
attestation. Readers of this document are assumed to be familiar with
the following terms: Evidence, Claim, Attestation Results (AR), Attester,
Verifier, Target Environment, Attesting Environment, Composite Device,
Lead Attester, Attestation Key, and Relying Party (RP).

The term "Certification Request" message is defined in {{RFC2986}}.
Specifications, such as {{RFC7030}}, later introduced the term
"Certificate Signing Request (CSR)" to refer to the Certification
Request message. While the term "Certification Signing Request"
would have been correct, the mistake was unnoticed. In the meanwhile
CSR is an abbreviation used beyond PKCS#10. Hence, it is equally
applicable to other protocols that use a different syntax and
even a different encoding, in particular this document also
considers messages in the Certificate Request Message Format (CRMF) {{RFC4211}}
to be "CSRs". In this document, the terms "CSR" and Certificate Request
message are used interchangeably.

# Architecture {#architecture}

{{fig-arch}} shows the high-level communication pattern of the RATS
background check model where the Attester transmits the Evidence in the
CSR to the RA and the CA, which is subsequently forwarded to the Verifier.
The Verifier appraises the received Evidence and computes an Attestation
Result, which is then processed by the RA/CA prior to the certificate
issuance.

In addition to the background check model, the RATS architecture also
specifies the passport model and combinations. See Section 5.2 of
{{RFC9334}} for a description of the passport model. The passport model
requires the Attester to transmit Evidence to the Verifier directly in order
to obtain the Attestation Result, which is then forwarded to the Relying
Party. This specification utilizes the background check model since CSRs are
often used as one-shot messages where no direct real-time interaction
between the Attester and the Verifier is possible.

Note that the Verifier is a logical role that may be included in the
RA/CA product. In this case, the Relying Party role and Verifier role collapse into a
single entity. The Verifier functionality can, however,
also be kept separate from the RA functionality, such as a utility or
library provided by the device manufacturer. For example,
security concerns may require parsers of Evidence formats to be logically
or physically separated from the core RA and CA functionality. The interface
by which the Relying Party passes Evidence to the Verifier and receives back
Attestation Results may be proprietary or standardized, but in any case is
out-of-scope for this document.

The diagram below shows an example data flow where Evidence is included in a
CSR. The CSR is parsed by the Registration Authority (RA) component of a
Certification Authority which extracts the Evidence and forwards it to a
trusted Verifier. The RA receives back an Attestation Result which it uses
to decide whether this Evidence meets its policy for certificate issuance
and if it does then the certificate request is forwarded to the Certification
Authority for issuance. This diagram overlays PKI entities with RATS roles in
parentheses.

~~~ aasvg
                          .-----------------.
                          |                 | Compare Evidence
                          |    (Verifier)   | against Appraisal
                          |                 | Policy
                          '------------+----'
                               ^       |
                      Evidence |       | Attestation
                               |       | Result (AR)
                               |       v
.------------.            .----|-------|----.                .-----.
|            +----------->|----'       '--->|--------------->|     |
| HSM        | Evidence   | Reg. Authority  | Attestation    | CA  |
| (Attester) | in CSR     | (Relying Party) | Result Meets   |     |
|            |            |                 | Cert policy?   |     |
'------------'            '-----------------'                '-----'
~~~
{: #fig-arch title="Example data flow demonstrating the architecture with Background Check Model."}

As discussed in RFC 9334, different security and privacy aspects need to be
considered. For example, Evidence may need to be protected against replay and
Section 10 of RFC 9334 lists approach for offering freshness. There are also
concerns about the exposure of persistent identifiers by utilizing attestation
technology, which are discussed in Section 11 of RFC 9334. Finally, the keying
material used by the Attester needs to be protected against unauthorized access,
and against signing arbitrary content that originated from outside the device.
This aspect is described in Section 12 of RFC 9334. Most of these aspects are,
however, outside the scope of this specification but relevant for use with a
given attestation technology. The focus of this specification is on the
transport of Evidence from the Attester to the Relying Party via existing
CSR messages.

# Information Model

## Interaction with an HSM

This specification is applicable both in cases where a CSR
is constructed internally or externally to the Attesting Environment, from the
point of view of the calling application.

Cases where the CSR is generated internally to the Attesting Environment
are straightforward: the HSM generates and embeds the Evidence and the corresponding
certification paths when constructing the CSR.

Cases where the CSR is generated externally may require extra round-trips of communication
between the CSR generator and the Attesting Environment, first to obtain
the necessary Evidence about the subject key, and then to use
the subject key to sign the CSR; for example, a CSR generated by
a popular crypto library about a subject key stored on a PKCS#11 {{PKCS11}} device.

As an example, assuming that the HSM is, or contains, the Attesting Environment and
some cryptographic library is assembling a CSR by interacting with the HSM over some
network protocol, then the interaction would conceptually be:

~~~ aasvg
                   +---------+          +-----+
                   | Crypto  |          | HSM |
                   | Library |          |     |
                   +---------+          +-----+
                        |                  |
                        | getEvidence()    |
                        |----------------->|
                        |                  |
                        |<-----------------|
+---------------------+ |                  |
| CSR = assembleCSR() |-|                  |
+---------------------+ |                  |
                        |                  |
                        | sign(CSR)        |
                        |----------------->|
                        |                  |
                        |<-----------------|
                        |                  |
~~~
{: #fig-csr-client-p11 title="Example interaction between CSR generator and HSM."}

## Encoding Strategy

To support a number of different use cases for the transmission of
Evidence and certificate chains in a CSR the structure
shown in {{fig-info-model}} is used.

On a high-level, the structure is composed as follows:
A PKCS#10 attribute or a CRMF extension contains one or more
EvidenceBundle structures. Each EvidenceBundle contains one or more
EvidenceStatement structures as well as one or more
CertificateChoices which enable to carry various format of
certificates.

~~~ aasvg
 +-------------------+
 | PKCS#10 Attribute |
 |       or          |
 | CRMF Extension    |
 +--------+----------+
          |
          |           (1 or more) +-------------------------+
          |         +-------------+ CertificateChoices      |
          |         |             +-------------------------+
          |         |             | Certificate OR          |
          |         |             | OtherCertificateFormat  |
   (1 or  |         |             +-------------------------+
    more) |         |      (1 or
 +--------+---------+-+     more) +-------------------+
 |  EvidenceBundle    +-----------+ EvidenceStatement |
 +--------------------+           +-------------------+
                                  | Type              |
                                  | Statement         |
                                  +-------------------+
~~~
{: #fig-info-model title="Information Model for CSR Evidence Conveyance."}

A conformant implementation of an entity parsing the CSR structures MUST be prepared
to parse certificates found in the corresponding EvidenceBundle structure to build
a certification path to validate the EvidenceStatement found in the same EvidenceBundle.
Hence, certificates need for validating EvidenceStatements are found in the same
EvidenceBundle.

The following use cases are supported, as described in the sub-sections below.

### Case 1 - Single Evidence Bundle

A single Attester, which only distributes Evidence without an attached certificate chain.
In the use case, the Verifier is assumed to be in possession of the certificate chain already
or the Verifier directly trusts the Attestation Key and therefore no certificate chain needs
to be conveyed in the CSR.
As a result, a single EvidenceBundle is included in a CSR that contains a single EvidenceStatement
without the CertificateChoices structure. {{fig-single-attester}} shows this use case.

~~~ aasvg
  +--------------------+
  |  EvidenceBundle    |
  +--------------------+
  | EvidenceStatement  |
  +--------------------+
~~~
{: #fig-single-attester title="Case 1: Single Evidence Bundle."}

### Case 2 - Single Evidence Bundle with Certificate Chain

A single Attester, which shares Evidence together with a certificate chain.
The CSR conveys a single EvidenceBundle with a single EvidenceStatement
and a single CertificateChoices structure. {{fig-single-attester-with-path}}
shows this use case.

~~~ aasvg
 +-------------------------+
 |  EvidenceBundle         |
 +-------------------------+
 | EvidenceStatement       |
 | CertificateChoices      |
 +-------------------------+
~~~
{: #fig-single-attester-with-path title="Case 2: Single Evidence Bundle with Certificate Chain."}

### Case 3 - Multiple Evidence Bundles each with Complete Certificate Chains

In a Composite Device, which contains multiple Attesters, a collection of Evidence
statements is obtained. In this use case, each Attester returns its Evidence together with a
certificate chain. As a result, multiple EvidenceBundle structures, each carrying
an EvidenceStatement and the corresponding CertificateAlternative structure with the
certification chain as provided by each Attester, are included in the CSR.
This may result in certificates being duplicated across multiple EvidenceBundles.
This approach does not require any processing capabilities
by a Lead Attester since the information is merely forwarded. {{fig-multiple-attesters}}
shows this use case.

~~~ aasvg
  +-------------------------+
  |  EvidenceBundle (1)     |\
  +-------------------------+ \ Provided by
  | EvidenceStatement       | / Attester 1
  | CertificateChoices      |/
  +-------------------------+
  |  EvidenceBundle (2)     |\
  +-------------------------+ \ Provided by
  | EvidenceStatement       | / Attester 2
  | CertificateChoices      |/
  +-------------------------+
~~~
{: #fig-multiple-attesters title="Case 3: Multiple Evidence Bundles each with Complete Certificate Chains."}

### Case 4 - Multiple Evidence Bundles with Certificate Transmission Optimization

In the last use case, a Composite Device with additional processing
capabilities of the Lead Attester parses the certificate chain provided by
all Attesters in the device and removes duplicate certificates. The
benefit of this approach is the reduced transmission payload size. There are several
implementation strategies and we show two in the sub-sections below.

Note: This specification does not support this optimization.

# ASN.1 Elements

##  Object Identifiers

This document references `id-pkix` and `id-aa`, both defined in {{!RFC5911}} and {{!RFC5912}}.

This document defines the arc depicted in {{code-ata-arc}}

~~~
-- Arc for Evidence types
id-ata OBJECT IDENTIFIER ::= { id-pkix (TBD1) }
~~~
{: #code-ata-arc title="New OID Arc for PKIX Evidence Statement Formats"}

## Evidence Attribute and Extension {#sec-evidenceAttr}

By definition, attributes within a PKCS#10 CSR are
typed as ATTRIBUTE and within a CRMF CSR are typed as EXTENSION.
This attribute definition contains one or more
Evidence bundles of type `EvidenceBundle` where each contain
one or more Evidence statements of a type `EvidenceStatement` along with
an optional certification path.
This structure allows for grouping Evidence statements that share a
certification path.

~~~
EVIDENCE-STATEMENT ::= TYPE-IDENTIFIER

EvidenceStatementSet EVIDENCE-STATEMENT ::= {
   ... -- None defined in this document --
}
~~~
{: #code-EvidenceStatementSet title="Definition of EvidenceStatementSet"}

The expression illustrated in {{code-EvidenceStatementSet}} maps ASN.1 Types for Evidence Statements to the OIDs
that identify them. These mappings are are used to construct
or parse EvidenceStatements. Evidence Statement formats are typically
defined in other IETF standards, other standards bodies,
or vendor proprietary formats along with corresponding OIDs that identify them.

This list is left unconstrained in this document. However, implementers can
populate it with the formats that they wish to support.

~~~
EvidenceStatements ::= SEQUENCE SIZE (1..MAX) OF EvidenceStatement

EvidenceStatement ::= SEQUENCE {
   type   EVIDENCE-STATEMENT.&id({EvidenceStatementSet}),
   stmt   EVIDENCE-STATEMENT.&Type({EvidenceStatementSet}{@type}),
   hint   UTF8String OPTIONAL
}
~~~
{: #code-EvidenceStatement title="Definition of EvidenceStatement"}

In {{code-EvidenceStatement}}, type is an OID that indicates the format of the value of stmt.

Based on the responsibilities of the different roles in the RATS architecture,
Relying Parties need to relay Evidence to Verifiers for evaluation and obtain
an Attestation Result in return. Ideally, the Relying Party should select a Verifier
based on the received Evidence without requiring the Relying Party to inspect the
Evidence itself. This "routing" decision is simple when there is only a single
Verifier configured for use by a Relying Party but gets more complex when there
are different Verifiers available and each of them capable of parsing only certain
Evidence formats.

In some cases, the EvidenceStatement.type OID will be sufficient information
for the Relying Party to correctly route it to an appropriate Verifier,
however since the type OID only identifies the general data format, it is possible
that multiple Verifiers are registered against the same type OID in which case the
Relying Party will either require additional parsing of the evidence statement, or
the Attester will be required to provide additional information.

To simplify the task for the Relying Party an optional field, the hint, is available
in the EvidenceStatement structure, as shown in {{code-EvidenceStatement}}. An
Attester MAY include the hint to the EvidenceStatement and it MAY be processed
by the Relying Party. The Relying Party MAY decide not to trust the information
embedded in the hint or policy MAY override any information provided by the Attester
via this hint.

When the Attester populates the hint, it MUST contain a fully qualified domain
name (FQDN) which uniquely identifies a Verifier.
The problem of mapping hint FQDNs to Verifiers, and the problem of FQDN collision
is out of scope for this specification; it is assumed that Attester and Verifier
makers can manage this appropriately on their own FQDN trees, however if this
becomes problematic then a public registry may be needed.

In a typical usage scenario, the Relying Party is pre-configured with
a list of trusted Verifiers and the corresponding hint values can be used to look
up appropriate Verifier. Tricking an Relying Party into interacting with an unknown
and untrusted Verifier must be avoided.

Usage of the hint field can be seen in the TPM2_attest example in
{{appdx-tpm2}} where the type OID indicates the OID
id-TcgAttestCertify and the corresponding hint identifies the Verifier as
"tpmverifier.example.com".

~~~
EvidenceBundles ::= SEQUENCE SIZE (1..MAX) OF EvidenceBundle

EvidenceBundle ::= SEQUENCE {
   evidence EvidenceStatements,
   certs SEQUENCE SIZE (1..MAX) OF CertificateChoices OPTIONAL
      -- CertificateChoices MUST only contain certificate or other
}
~~~

The CertificateChoices structure defined in [RFC6268] allows for carrying certificates in the default X.509 [RFC5280] format, or in other non-X.509 certificate formats. CertificateChoices MUST only contain certificate or other. CertificateChoices MUST NOT contain extendedCertificate, v1AttrCert, or v2AttrCert. Note that for non-ASN.1 certificate formats, the CertificateChoices MUST use `other [3]` with an `OtherCertificateFormat.Type` of `OCTET STRING`, and then can carry any binary data.


~~~
id-aa-evidence OBJECT IDENTIFIER ::= { id-aa 59 }

-- For PKCS#10
attr-evidence ATTRIBUTE ::= {
  TYPE EvidenceBundles
  COUNTS MAX 1
  IDENTIFIED BY id-aa-evidence
}

-- For CRMF
ext-evidence EXTENSION ::= {
  SYNTAX EvidenceBundles
  IDENTIFIED BY id-aa-evidence
}
~~~
{: #code-extensions title="Definitions of CSR attribute and extension"}

The Extension variant illustrated in {{code-extensions}} is intended only for use within CRMF CSRs and is NOT RECOMMENDED to be used within X.509 certificates due to the privacy implications of publishing Evidence about the end entity's hardware environment. See {{sec-con-publishing-x509}} for more discussion.

The `certs` field contains a set of certificates that
is intended to validate the contents of an Evidence statement
contained in `evidence`, if required. The set of certificates should contain
the certificate that contains the public key needed to directly validate the
`evidence`. Additional certificates may be provided, for example, to chain the
Evidence signer key  back to an agreed upon trust anchor. No order is implied, it is
up to the Attester and its Verifier to agree on both the order and format
of certificates contained in `certs`.

This specification places no restriction on mixing certificate types within the `certs` field. For example a non-X.509 Evidence signer certificate MAY chain to a trust anchor via a chain of X.509 certificates. It is up to the Attester and its Verifier to agree on supported certificate formats.


By the nature of the PKIX ASN.1 classes [[RFC5912]], there are multiple ways to convey multiple Evidence statements: by including multiple copies of `attr-evidence` or `ext-evidence`, multiple values within the attribute or extension, and finally, by including multiple `EvidenceStatement`s within an `EvidenceBundle`. The latter is the preferred way to carry multiple Evidence statements. Implementations MUST NOT place multiple copies of `attr-evidence` into a PKCS#10 CSR due to the `COUNTS MAX 1` declaration, and SHOULD NOT place multiple copies of `EvidenceBundles` into an `AttributeSet`. In a CRMF CSR, implementers SHOULD NOT place multiple copies of `ext-evidence` and SHOULD NOT place multiple copies of `EvidenceBundles` into an `ExtensionSet`.


# IANA Considerations

IANA is requested to open two new registries, allocate a value
from the "SMI Security for PKIX Module Identifier" registry for the
included ASN.1 module, and allocate values from "SMI Security for
S/MIME Attributes" to identify two attributes defined within.

##  Module Registration - SMI Security for PKIX Module Identifier

-  Decimal: IANA Assigned - **Replace TBDMOD**
-  Description: CSR-ATTESTATION-2023 - id-mod-pkix-attest-01
-  References: This Document

##  Object Identifier Registrations - SMI Security for S/MIME Attributes

- Evidence Statement
  - Decimal: IANA Assigned - This was early-allocated as `59` so that we could generate the sample data.
  - Description: id-aa-evidence
  - References: This Document


##  "SMI Security for PKIX Evidence Statement Formats" Registry

IANA is asked to create a registry for Evidence Statement Formats within
the SMI-numbers registry, allocating an assignment from id-pkix ("SMI
Security for PKIX" Registry) for the purpose.

-  Decimal: IANA Assigned - **replace TBD1**
-  Description: id-ata
-  References: This document
-  Initial contents: None
-  Registration Regime: Specification Required.
   Document must specify an EVIDENCE-STATEMENT definition to which this
   Object Identifier shall be bound.

Columns:

-  Decimal: The subcomponent under id-ata
-  Description: Begins with id-ata
-  References: RFC or other document

## Attestation Evidence OID Registry

IANA is asked to create a registry that helps developers to find
OID/Evidence mappings.

Registration requests are evaluated using the criteria described in
the registration template below after a three-week review period on
the [[TBD]] mailing list, with the advice of one or more Designated
Experts {{RFC8126}}.  However, to allow for the allocation of values
prior to publication, the Designated Experts may approve registration
once they are satisfied that such a specification will be published.

Registration requests sent to the mailing list for review should use
an appropriate subject (e.g., "Request to register attestation
evidence: example").

IANA must only accept registry updates from the Designated Experts
and should direct all requests for registration to the review mailing
list.

### Registration Template

The registry has the following columns:

- OID: The OID number, which has already been allocated. IANA does
not allocate OID numbers for use with this registry.

- Description: Brief description of the use of the Evidence and the
registration of the OID.

- Reference(s): Reference to the document or documents that register
the OID for use with a specific attestation technology, preferably
including URIs that can be used to retrieve copies of the documents.
An indication of the relevant sections may also be included but is not
required.

- Change Controller: For Standards Track RFCs, list the "IESG".  For
others, give the name of the responsible party. In most cases the
third party requesting registration in this registry will also be the
party that registered the OID.

### Initial Registry Contents

The initial registry contents is shown in the table below.
It lists entries for several evidence encoding including an entry for the Conceptual Message Wrapper (CMW) {{I-D.ietf-rats-msg-wrap}}.

| OID              | Description                  | Reference(s)     | Change Controller |
|------------------|------------------------------|----------------  |-------------------|
| 2 23 133 5 4 1   | tcg-dice-tcbinfo             | {{TCGOIDREG}}   |  TCG              |
| 2 23 133 5 4 5   | tcg-dice-multitcbinfo        | {{TCGOIDREG}}   |  TCG              |
| 2 23 133 5 4 6   | tcg-dice-uccs-evidence       | {{TCGOIDREG}}   |  TCG              |
| 2 23 133 5 4 7   | tcg-dice-manifest-evidence   | {{TCGOIDREG}}   |  TCG              |
| 2 23 133 5 4 8   | tcg-dice-multi-tcbinfo-comp  | {{TCGOIDREG}}   |  TCG              |
| 2 23 133 5 4 9   | tcg-dice-cmw                 | {{TCGOIDREG}}   |  TCG              |
| 2 23 133 20 1    | tcg-attest-tpm-certify       | {{TCGOIDREG}}   |  TCG              |
{: #tab-ae-reg title="Initial Contents of the Attestation Evidence OID Registry"}

The current registry values can be retrieved from the IANA online website.

# Security Considerations

A PKCS#10 or CRMF Certification Request message typically consists of a
distinguished name, a public key, and optionally a set of attributes,
collectively signed by the entity requesting certification.
In general usage, the private key used to sign the CSR MUST be different from the
Attesting Key utilized to sign Evidence about the Target
Environment, though exceptions MAY be made where CSRs and Evidence are involved in
bootstrapping the Attesting Key.
To demonstrate that the private
key applied to sign the CSR is generated, and stored in a secure
environment that has controls to prevent theft or misuse (including
being non-exportable / non-recoverable), the Attesting Environment
has to collect claims about this secure environment (or Target
Environment, as shown in {{fig-attester}}).

{{fig-attester}} shows the interaction inside an Attester. The
Attesting Environment, which is provisioned with an Attestation Key,
retrieves claims about the Target Environment. The Target
Environment offers key generation, storage and usage, which it
makes available to services. The Attesting Environment collects
these claims about the Target Environment and signs them and
exports Evidence for use in remote attestation via a CSR.

~~~ aasvg
                   ^
                   |CSR with
                   |Evidence
     .-------------+-------------.
     |                           |
     |       CSR Library         |<-----+
     |                           |      |
     '---------------------------'      |
            |  ^         ^              |
 Private    |  | Public  | Signature    |
 Key        |  | Key     | Operation    |
 Generation |  | Export  |              |
            |  |         |              |
 .----------|--|---------|------------. |
 |          |  |         |    Attester| |
 |          v  |         v    (HSM)   | |
 |    .-----------------------.       | |
 |    | Target Environment    |       | |
 |    | (with key generation, |       | |
 |    | storage and usage)    |       | |
 |    '--------------+--------'       | |
 |                   |                | |
 |           Collect |                | |
 |            Claims |                | |
 |                   |                | |
 |                   v                | |
 |             .-------------.        | |
 |Attestation  | Attesting   |        | |
 |   Key ----->| Environment +----------+
 |             | (Firmware)  |Evidence|
 |             '-------------'        |
 |                                    |
 '------------------------------------'
~~~
{: #fig-attester title="Interaction between Attesting and Target Environment"}

{{fig-attester}} places the CSR library outside the Attester, which
is a valid architecture for certificate enrollment.
The CSR library may also be located
inside the trusted computing base. Regardless of the placement
of the CSR library, an Attesting Environment MUST be able to collect
claims about the Target Environment such that statements about
the storage of the keying material can be made.
For the Verifier, the provided Evidence must allow
an assessment to be made whether the key used to sign the CSR
is stored in a secure location and cannot be exported.

Evidence communicated in the attributes and structures defined
in this document are meant to be used in a CSR. It is up to
the Verifier and to the Relying Party (RA/CA) to place as much or
as little trust in this information as dictated by policies.

This document defines the transport of Evidence of different formats
in a CSR. Some of these encoding formats are based on standards
while others are proprietary formats. A Verifier will need to understand
these formats for matching the received claim values against policies.

Policies drive the processing of Evidence at the Verifier: the Verifier's
Appraisal Policy for Evidence will often be based on specifications by the manufacturer
of a hardware security module, a regulatory agency, or specified by an
oversight body, such as the CA Browser Forum. The Code-Signing Baseline
Requirements {{CSBR}} document
is an example of such a policy that has
been published by the CA Browser Forum and specifies certain properties,
such as non-exportability, which must be enabled for storing
publicly-trusted code-signing keys. Other
policies influence the decision making at the Relying Party when
evaluating the Attestation Result. The Relying Party is ultimately
responsible for making a decision of what information in the Attestation
Result it will accept. The presence of the attributes defined in this
specification provide the Relying Party with additional assurance about
an Attester. Policies used at the Verifier and the Relying Party are
implementation dependent and out of scope for this document. Whether to
require the use of Evidence in a CSR is out-of-scope for this document.

## Freshness

Evidence generated by an Attester generally needs to be fresh to provide
value to the Verifier since the configuration on the device may change
over time. Section 10 of {{RFC9334}} discusses different approaches for
providing freshness, including a nonce-based approach, the use of timestamps
and an epoch-based technique.  The use of nonces requires that nonce to be provided by
the Relying Party in some protocol step prior to Evidence and CSR generation,
and the use of timestamps requires synchronized clocks which cannot be
guaranteed in all operating environments. Epochs also require an out-of-band
communication channel.
This document only specifies how to carry existing Evidence formats inside a CSR,
and so issues of synchronizing freshness data is left to be handled, for example,
via certificate management protocols.
Developers, operators, and designers of protocols, which embed
Evidence-carrying-CSRs, MUST consider what notion of freshness is
appropriate and available in-context; thus the issue of freshness is
left up to the discretion of protocol designers and implementers.

In the case of Hardware Security Modules (HSM), the definition of "fresh" is somewhat ambiguous in the context
of CSRs, especially considering that non-automated certificate enrollments
are often asynchronous, and considering the common practice of re-using the
same CSR for multiple certificate renewals across the lifetime of a key.
"Freshness" typically implies both asserting that the data was generated
at a certain point-in-time, as well as providing non-replayability.
Certain use cases may have special properties impacting the freshness
requirements. For example, HSMs are typically designed to not allow downgrade
of private key storage properties; for example if a given key was asserted at
time T to have been generated inside the hardware boundary and to be
non-exportable, then it can be assumed that those properties of that key
will continue to hold into the future.


## Publishing evidence in an X.509 extension {#sec-con-publishing-x509}

This document specifies an Extension for carrying Evidence in a CRMF Certificate Signing Request (CSR), but it is intentionally NOT RECOMMENDED for a CA to copy the ext-evidence extension into the published certificate.
The reason for this is that certificates are considered public information and the Evidence might contain detailed information about hardware and patch levels of the device on which the private key resides.
The certificate requester has consented to sharing this detailed device information with the CA but might not consent to having these details published.
These privacy considerations are beyond the scope of this document and may require additional signaling mechanisms in the CSR to prevent unintended publication of sensitive information, so we leave it as "NOT RECOMMENDED". Often, the correct layer at which to address this is either in certificate profiles, a Certificate Practice Statement (CPS), or in the protocol or application that carries the CSR to the RA/CA where a flag can be added indicating whether the RA/CA should consider the evidence to be public or private.

## Type OID and verifier hint

The `EvidenceStatement` includes both a `type` OID and a free form `hint` field with which the Attester can provide information to the Relying Party about which Verifier to invoke to parse a given piece of Evidence.
Care should be taken when processing these data since at the time they are used, they are not yet verified. In fact, they are protected by the CSR signature but not by the signature from the Attester and so could be maliciously replaced in some cases.
The authors' intent is that the `type` OID and `hint` will allow an RP to select between Verifier with which it has pre-established trust relationships, such as Verifier libraries that have been compiled in to the RP application.
As an example, the `hint` may take the form of an FQDN to uniquely identify a Verifier implementation, but the RP MUST NOT blindly make network calls to unknown domain names and trust the results.
Implementers should also be cautious around `type` OID or `hint` values that cause a short-circuit in the verification logic, such as `None`, `Null`, `Debug`, empty CMW contents, or similar values that could cause the Evidence to appear to be valid when in fact it was not properly checked.

## Additional security considerations

In addition to the security considerations listed here, implementers should be familiar with the security considerations of the specifications on this this depends: PKCS#10 [RFC2986], CRMF [4211], as well as general security concepts relating to evidence and remote attestation; many of these concepts are discussed in the Remote ATtestation prodedureS (RATS) Architecture [RFC9334] sections 6 Roles and Entities, 7 Trust Model, 9 Freshness, 11 Privacy Considerations, and 12 Security Considerations. Implementers should also be aware of any security considerations relating to the specific evidence format being carried within the CSR.

--- back


# Examples

This section provides several examples and sample data for embedding Evidence
in CSRs. The first example embeds Evidence produced by a TPM in the CSR.
The second example conveys an Arm Platform Security Architecture token,
which provides claims about the used hardware and software platform,
into the CSR.

After publication of this document, additional examples and sample data will
be collected at the following GitHub repository {{SampleData}}:

https://github.com/lamps-wg/csr-attestation-examples


## Extending EvidenceStatementSet

As defined in {{sec-evidenceAttr}}, EvidenceStatementSet acts as a way to provide an ASN.1 compiler or
runtime parser with a list of OBJECT IDENTIFIERs that are known to represent EvidenceStatements
-- and are expected to appear in an EvidenceStatement.type field, along with
the ASN.1 type that should be used to parse the data in the associated EvidenceStatement.stmt field.
Essentially this is a mapping of OIDs to data structures. Implementers are expected to populate it
with mappings for the Evidence types that their application will be handling.

This specification aims to be agnostic about the type of data being carried, and therefore
does not specify any mandatory-to-implement Evidence types.

As an example of how to populate EvidenceStatementSet, implementing the TPM 2.0 and PSA Evidence types
given below would result in the following EvidenceStatementSet definition:

~~~
EvidenceStatementSet EVIDENCE-STATEMENT ::= {
  --- TPM 2.0
  { Tcg-attest-tpm-certify IDENTIFIED BY tcg-attest-tpm-certify },
  ...,

  --- PSA
  { OCTET STRING IDENTIFIED BY { 1 3 6 1 5 5 7 1 99 } }
}
~~~


##  TPM V2.0 Evidence in CSR {#appdx-tpm2}

This section describes TPM2 key attestation for use in a CSR.

This is a complete and canonical example that can be used to test parsers implemented against this specification. Readers who wish the sample data may skip to {{appdx-tpm-example}}; the following sections explain the TPM-specific data structures needed to fully parse the contents of the evidence statement.

### TCG Key Attestation Certify

There are several ways in TPM2 to provide proof of a key's properties.
(i.e., key attestation). This description uses the simplest and most generally
expected to used which is the TPM2_Certify and the TPM2_ReadPublic commands.

### TCG OIDs

The OIDs in this section are defined by TCG
TCG has a registered arc of 2.23.133

~~~
tcg OBJECT IDENTIFIER ::= { 2 23 133 }

tcg-kp-AIKCertificate OBJECT IDENTIFIER ::= { id-tcg 8 3 }

tcg-attest OBJECT IDENTIFIER ::= { tcg 20 }

tcg-attest-tpm-certify OBJECT IDENTIFIER ::= { tcg-attest 1 }
~~~
The tcg-kp-AIKCertificate OID in extendedKeyUsage identifies an AK Certificate in RFC 5280 format defined by TCG. This
certificate would be a certificate in the EvidenceBundle defined in {{sec-evidenceAttr}}. (Note: The abbreviation AIK was used in
TPM 1.2 specification. TPM 2.0 specifications use the abbreviation AK. The abbreviations are interchangeable.)

### TPM2 AttestationStatement {#appdx-tcg-attest-tpm-certify}

The EvidenceStatement structure contains a sequence of two fields:
a type and a stmt. The 'type' field contains the OID of the Evidence format and it is
set to tcg-attest-tpm-certify. The content of the structure shown below is placed into
the stmt, which is a concatenation of existing TPM2 structures. These structures
will be explained in the rest of this section.

~~~
Tcg-csr-tpm-certify ::= SEQUENCE {
  tpmSAttest       OCTET STRING,
  signature        OCTET STRING,
  tpmTPublic       OCTET STRING OPTIONAL
}
~~~

### Introduction to TPM2 concepts

The definitions in the following sections are specified by the Trusted Computing Group (TCG). TCG specification including the TPM2 set of specifications [TPM20], specifically Part 2 defines the TPM 2.0 structures.
Those familiar with TPM2 concepts may skip to {{appdx-tcg-attest-tpm-certify}} which defines an ASN.1 structure
specific for bundling a TPM attestation into an EvidenceStatement, and {{appdx-tpm-example}} which provides the example.
For those unfamiliar with TPM2 concepts this section provides only the minimum information to understand TPM2
Attestation in CSR and is not a complete description of the technology in general.

### TCG Objects and Key Attestation

This provides a brief explanation of the relevant TPM2 commands and data
structures needed to understand TPM2 Attestation used in this RFC.
NOTE: The TPM2 specification used in this explanation is version 1.59,
section number cited are based on that version. Note also that the TPM2
specification comprises four documents: Part 1: Architecture; Part 2: Structures;
Part 3: Commands; Part 4: Supporting Routines.

Note about convention:
All structures starting with TPM2B_ are:

* a structure that is a sized buffer where the size of the buffer is contained in a 16-bit, unsigned value.
* The first parameter is the size in octets of the second parameter. The second parameter may be any type.

A full explanation of the TPM structures is outside the scope of this document. As a
simplification references to TPM2B_ structures will simply use the enclosed
TPMT_ structure by the same name following the '_'.

#### TPM2 Object Names

All TPM2 Objects (e.g., keys are key objects which is the focus of this specification).
A TPM2 object name is persistent across the object's life cycle whether the TPM2
object is transient or persistent.

A TPM2 Object name is a concatenation of a hash algorithm identifier and a hash of
the TPM2 Object's TPMT_PUBLIC.

~~~
     Name ≔ nameAlg || HnameAlg (handle→publicArea)
     nameAlg is a TCG defined 16 bit algorithm identifier
~~~

publicArea is the TPMT_PUBLIC structure for that TPM2 Object.

The size of the Name field can be derived by examining the nameAlg value, which defines
the hashing algorithm and the resulting size.

The Name field is returned in the TPM2B_ATTEST data field.

~~~
     typedef struct {
          TPM_GENERATED magic;
          TPMI_ST_ATTEST type;
          TPM2B_NAME qualifiedSigner;
          TPM2B_DATA extraData;
          TPMS_CLOCK_INFO clockInfo;
          UINT64 firmwareVersion;
          TPMU_ATTEST attested;
     } TPMS_ATTEST;
~~~

where for a key object the attested field is

~~~
     typedef struct {
          TPM2B_NAME name;
          TPM2B_NAME qualifiedName;
     } TPMS_CERTIFY_INFO;
~~~

#### TPM2 Public Structure

Any TPM2 Object has an associated TPM2 Public structure defined
as TPMT_PUBLIC. This is defined below as a 'C' structure. While there
are many types of TPM2 Objects each with its own specific TPMT_PUBLIC
structure (handled by the use of 'unions') this document will specifically
define TPMT_PUBLIC for a TPM2 key object.

~~~
     typedef struct {
          TPMI_ALG_PUBLIC type;
          TPMI_ALG_HASH nameAlg;
          TPMA_OBJECT objectAttributes;
          TPM2B_DIGEST authPolicy;
          TPMU_PUBLIC_PARMS parameters;
          TPMU_PUBLIC_ID unique;
     } TPMT_PUBLIC;
~~~

Where:
* type and nameAlg are 16 bit TCG defined algorithms.
* objectAttributes is a 32 bit field defining properties of the object, as shown below

~~~
     typedef struct TPMA_OBJECT {
          unsigned Reserved_bit_at_0 : 1;
          unsigned fixedTPM : 1;
          unsigned stClear : 1;
          unsigned Reserved_bit_at_3 : 1;
          unsigned fixedParent : 1;
          unsigned sensitiveDataOrigin : 1;
          unsigned userWithAuth : 1;
          unsigned adminWithPolicy : 1;
          unsigned Reserved_bits_at_8 : 2;
          unsigned noDA : 1;
          unsigned encryptedDuplication : 1;
          unsigned Reserved_bits_at_12 : 4;
          unsigned restricted : 1;
          unsigned decrypt : 1;
          unsigned sign : 1;
          unsigned x509sign : 1;
          unsigned Reserved_bits_at_20 : 12;
     } TPMA_OBJECT;
~~~

* authPolicy is the Policy Digest needed to authorize use of the object.
* Parameters are the object type specific public information about the key.
     * For key objects, this would be the key's public parameters.
* unique is the identifier for parameters

The size of the TPMT_PUBLIC is provided by the following structure:

~~~
     typedef struct {
          UINT16     size;
          TPMT_PUBLIC publicArea;
     } TPM2B_PUBLIC;
~~~

#### TPM2 Signatures

TPM2 signatures use a union where the first field (16 bits) identifies
the signature scheme. The example below shows an RSA signature where
TPMT_SIGNATURE->sigAlg will indicate to use TPMS_SIGNATURE_RSA
as the signature.

~~~
     typedef struct {
          TPMI_ALG_SIG_SCHEME sigAlg;
          TPMU_SIGNATURE signature;
     } TPMT_SIGNATURE;

     typedef struct {
          TPMI_ALG_HASH hash;
          TPM2B_PUBLIC_KEY_RSA sig;
     } TPMS_SIGNATURE_RSA;
~~~

#### Attestation Key {#attestation-key}

The uniquely identifying TPM2 key is the Endorsement Key (the EK). As this is a privacy
sensitive key, the EK is not directly used to attest to any TPM2 asset. Instead,
the EK is used by an Attestation CA to create an Attestation Key (the AK). The AK is
assumed trusted by the Verifier and is assume to be loaded in the TPM during the execution
of the process described in the subsequent sections. The description of how to create the AK is outside
the scope of this document.

#### Attester Processing

The only signed component is the TPM2B_ATTEST structure, which returns
only the (key's) Name and the signature computed over the Name but no detailed information
about the key. As the Name is comprised of public information, the Name can
be calculated by the Verifier but only if the Verify knows all the public
information about the Key.

The Attester's processing steps are as follows:

Using the TPM2 command TPM2_Certify obtain the TPM2B_ATTEST and TPMT_SIGNATURE structures
from the TPM2. The signing key for TPMT_SIGNATURE is an Attention Key (or AK), which is
assumed to be available to the TPM2 upfront. More details are provided in {{attestation-key}}

The TPM2 command TPM2_Certify takes the following input:

 * TPM2 handle for Key (the key to be attested to)
 * TPM2 handle for the AK (see {{attestation-key}})

It produces the following output:

 * TPM2B_ATTEST in binary format
 * TPMT_SIGNATURE in binary format

Then, using the TPM2 command TPM2_ReadPublic obtain the Keys TPM2B_PUBLIC structure.
While the Key's public information can be obtained by the Verifier in a number
ways, such as storing it from when the Key was created, this may be impractical
in many situations. As TPM2 provided a command to obtain this information, this
specification will include it in the TPM2 Attestation CSR extension.

The TPM2 command TPM2_ReadPublic takes the following input:

 * TPM2 handle for Key (the key to be attested to)

It produces the following output:

 * TPM2B_PUBLIC in binary format

#### Verifier Processing

The Verifier has to perform the following steps once it receives the Evidence:

* Verify the TPM2B_ATTEST using the TPMT_SIGNATURE.
* Use the Key's "expected" Name from the provided TPM2B_PUBLIC structure.
If Key's "expected" Name equals TPM2B_ATTEST->attestationData then returned TPM2B_PUBLIC is the verified.

### Sample CSR {#appdx-tpm-example}

This CSR demonstrates a certification request for a key stored in a TPM using the following structure:

~~~
CSR {
  attributes {
    id-aa-evidence {
      EvidenceBundles {
        EvidenceBundle {
          EvidenceStatements {
            EvidenceStatement {
              type: tcg-attest-tpm-certify,
              stmt: <TcgAttestTpmCertify_data>
              hint: "tpmverifier.example.com"
            }
          },
          certs {
            akCertificate,
            caCertificate
          }
        }
      }
    }
  }
}
~~~

Note that this example demonstrates most of the features of this specification:

- The data type is identified by the OID id-TcgCsrCertify contained in the `EvidenceStatement.type` field.
- The signed evidence is carried in the `EvidenceStatement.stmt` field.
- The `EvidenceStatement.hint` provides information to the Relying Party about which Verifier (software) will be able to correctly parse this data. Note that the `type` OID indicates the format of the data, but that may itself be a wrapper format that contains further data in a proprietary format. In this example, the hint says that software from the package `"tpmverifier.example.com"` will be able to parse this data.
- The evidence statement is accompanied by a certificate chain in the `EvidenceBundle.certs` field which can be used to verify the signature on the evidence statement. How the Verifier establishes trust in the provided certificates is outside the scope of this specification.

Features of this specification that are not demonstrated by this example are:

- An EvidenceBundle containing multiple EvidenceStatements that share a certificate chain.
- Multiple EvidenceBundles that each have their own certificate chain.

~~~
{::include sampledata/tcgAttestTpmCertify.pem}
~~~

## PSA Attestation Token in CSR

The Platform Security Architecture (PSA) Attestation Token is
defined in {{I-D.tschofenig-rats-psa-token}} and specifies
claims to be included in an Entity Attestation
Token (EAT). {{I-D.bft-rats-kat}} defines key attestation
based on the EAT format. In this section the platform
attestation offered by {{I-D.tschofenig-rats-psa-token}}
is combined with key attestation by binding the
key attestation token (KAT) to the platform attestation token (PAT)
with the help of the nonce. For details see {{I-D.bft-rats-kat}}.
The resulting KAT-PAT bundle is, according to
{{Section 5.1 of I-D.bft-rats-kat}}, combined in a CMW collection
{{I-D.ietf-rats-msg-wrap}}.

The encoding of this KAT-PAT bundle is shown in the example below.

~~~
EvidenceBundles
 +
 |
 +-> EvidenceBundle
      +
      |
      +->  EvidenceStatement
            +
            |
            +-> type: OID for CMW Collection
            |         1 3 6 1 5 5 7 1 TBD
            |
            +-> stmt: KAT/PAT CMW Collection
~~~

The value in EvidenceStatement->stmt is based on the
KAT/PAT example from {{Section 6 of I-D.bft-rats-kat}} and
the result of CBOR encoding the CMW collection shown below
(with line-breaks added for readability purposes):

~~~
{
  "kat":
    h'd28443A10126A058C0A30A5820B91B03129222973C214E42BF31D68
      72A3EF2DBDDA401FBD1F725D48D6BF9C8171909C4A40102200121
      5820F0FFFA7BA35E76E44CA1F5446D327C8382A5A40E5F29745DF
      948346C7C88A5D32258207CB4C4873CBB6F097562F61D5280768C
      D2CFE35FBA97E997280DBAAAE3AF92FE08A101A40102200121582
      0D7CC072DE2205BDC1537A543D53C60A6ACB62ECCD890C7FA27C9
      E354089BBE13225820F95E1D4B851A2CC80FFF87D8E23F22AFB72
      5D535E515D020731E79A3B4E47120584056F50D131FA83979AE06
      4E76E70DC75C070B6D991AEC08ADF9F41CAB7F1B7E2C47F67DACA
      8BB49E3119B7BAE77AEC6C89162713E0CC6D0E7327831E67F3284
      1A',
  "pat":
    h'd28443A10126A05824A10A58205CA3750DAF829C30C20797EDDB794
      9B1FD028C5408F2DD8650AD732327E3FB645840F9F41CAB7F1B7E
      2C47F67DACA8BB49E3119B7BAE77AEC6C89162713E0CC6D0E7327
      831E67F32841A56F50D131FA83979AE064E76E70DC75C070B6D99
      1AEC08AD'
}
~~~

# ASN.1 Module

~~~
{::include CSR-ATTESTATION-2023.asn}
~~~

## TCG DICE ConceptualMessageWrapper in CSR

This section gives an example of extending the ASN.1 module above to carry an existing ASN.1-based evidence statement.
The example used is the Trusted Computing Group DICE Attestation Conceptual Message Wrapper, as defined in {{TCGDICE1.1}}.

~~~
{::include CSR-ATTESTATION-WITH-DICE-CMW.asn}
~~~

## TCG DICE ConceptualMessageWrapper in CSR

This section gives an example of extending the ASN.1 module above to carry an existing ASN.1-based evidence statement.
The example used is the Trusted Computing Group DiceTcbInfo, as defined in {{TCGDICE1.1}}.

~~~
{::include CSR-ATTESTATION-WITH-DiceTcbInfo.txt}
~~~

# Acknowledgments

This specification is the work of a design team created by the chairs of the
LAMPS working group. The following persons, in no specific order,
contributed to the work: Richard Kettlewell, Chris Trufan, Bruno Couillard,
Jean-Pierre Fiset, Sander Temme, Jethro Beekman, Zsolt Rózsahegyi, Ferenc
Pető, Mike Agrenius Kushner, Tomas Gustavsson, Dieter Bong, Christopher Meyer,
Michael StJohns, Carl Wallace, Michael Richardson, Tomofumi Okubo, Olivier
Couillard, John Gray, Eric Amador, Johnson Darren, Herman Slatman, Tiru Reddy,
Corey Bonnell, Argenius Kushner, James Hagborg, A.J. Stein, John Kemp, Ned
Smith.

We would like to specifically thank Mike StJohns for his work on an earlier
version of this draft.

We would also like to specifically thank Monty Wiseman for providing the
appendix showing how to carry a TPM 2.0 Attestation, and to Corey Bonnell for helping with the hackathon scripts to bundle it into a CSR.

Finally, we would like to thank Andreas Kretschmer and Thomas Fossati for their
feedback based on implementation experience, and Daniel Migault and Russ Housley
for their review comments.
