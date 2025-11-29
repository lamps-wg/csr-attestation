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
    org: Intel Corporation
    country: United States
    email: ned.smith@intel.com

normative:
  RFC9334:
  RFC6268:
  RFC5912:
  RFC4211:
  RFC2986:
  RFC5280:
  RFC3986:

informative:
  RFC8126:
  RFC5226:
  I-D.ietf-rats-msg-wrap:
  I-D.bft-rats-kat:
  RFC7030:
  I-D.ietf-rats-daa:
  I-D.ietf-lamps-attestation-freshness:
  I-D.tschofenig-rats-psa-token:
  I-D.ffm-rats-cca-token:
  I-D.ietf-rats-endorsements:
  I-D.ietf-rats-ar4si:
  CSBR:
    author:
      org: CA/Browser Forum
    title: Baseline Requirements for Code-Signing Certificates, v.3.7
    date: February 28, 2024
    target: https://cabforum.org/uploads/Baseline-Requirements-for-the-Issuance-and-Management-of-Code-Signing.v3.7.pdf
  TCGRegistry:
    author:
      org: "Trusted Computing Group"
    title: "TCG OID Registry"
    target: https://trustedcomputinggroup.org/resource/tcg-oid-registry/
    date: October, 2024
  TCGDICE1.2:
    author:
      org: "Trusted Computing Group"
    title: "DICE Attestation Architecture"
    target: https://trustedcomputinggroup.org/wp-content/uploads/DICE-Attestation-Architecture-v1.2_pub.pdf
    date: April, 2025
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

This specification defines an attribute and an extension that allow for conveyance of RATS conceptual messages (see {{Section 8 of RFC9334}}, such as Evidence, Endorsements and
Attestation Results, in Certificate Signing Requests (CSRs), such as PKCS#10 or Certificate Request Message Format (CRMF) payloads. This provides an elegant and automatable mechanism for transporting attestation data to a Certification Authority.

Including Evidence, Endorsements and Attestation Results along with a CSR can help to improve the assessment of the security posture for the private key, and can help the Certification Authority to assess whether it satisfies the requested certificate profile.

--- middle

# Introduction

When requesting a certificate from a Certification Authority (CA), a PKI end entity may wish to include RATS conceptual messages (see {{Section 8 of RFC9334}}, such as Evidence, Endorsements {{I-D.ietf-rats-endorsements}} and
Attestation Results {{I-D.ietf-rats-ar4si}}, of the security properties of its environments in which the private keys are stored in that request.

Evidence and Endorsements are appraised by Verifiers, which typically produces Attestation Results that serve as input for validating incoming certificate requests against specified certificate policies.
Verifiers are associated with Registration Authorities (RAs) or CAs and function as logical entities responsible for processing Evidence and Endorsements in order to produce Attestation Results.
As remote attestation technology matures, it is natural for a Certification Authority to rely on remote attestation data for proof that the requesting entity is in a state that matches the certificate profile. This is referred to as the RATS Background Check Model, and is illustrated in {{fig-arch-background}}.

Alternatively, the Attester might have a direct connection to a Verifier to which it presents its Evidence and Endorsements, and receives back an Attestation Result signed by the Verifier which it can include directly in the CSR and save the RA / CA from needing a local Verifier. This is referred to as the RATS Passport Model, and is illustrated in {{fig-arch-passport}}.

At the time of writing, the most pressing example of the need for remote attestation in certificate enrollment is the Code-Signing Baseline Requirements (CSBR) document maintained by the CA/Browser Forum {{CSBR}}, which requires compliant CAs to "ensure that a Subscriber’s Private Key is generated, stored,
and used in a secure environment that has controls to prevent theft or misuse", which is a natural fit to enforce via remote attestation.

This specification defines an attribute and an extension that allow for conveyance of Evidence, Endorsements, and Attestation Results in Certificate Signing Requests (CSRs), such as PKCS#10 {{RFC2986}} or Certificate Request Message Format (CRMF) {{RFC4211}} payloads.
This CSR extension satisfies CA/B Forum's CSBR {{CSBR}} requirements for key protection assurance, provided that the CSR carries attestation data that the RA / CA can parse to obtain the assurance that it needs to satisfy its certificate issuance policies.

As outlined in the IETF RATS architecture {{RFC9334}}, an Attester (typically a device) produces a signed collection of Claims that constitute Evidence about its running environment(s).
The terms "attestation" or "remote attestation" are not explicitly defined in RFC 9334 but the activity of "attestation" is clarified in {{?RFC9683}}.
It refers to the process of generating and evaluating remote attestation Evidence and Endorsements.

This document relies on {{architecture}} as the foundation for how the various roles within the RATS architecture correspond to a certificate requester and a CA/RA.

Several standard and proprietary remote attestation technologies are in use at the time of writing. This specification thereby is intended to be as technology-agnostic as is feasible with respect to implemented remote attestation technologies. Hence, this specification focuses on (1) the conveyance of Evidence, Endorsements, and Attestation Results via CSRs while making minimal assumptions about content or format of the transported payload and (2) the conveyance of sets of certificates used for validation of Evidence, Endorsements, and Attestation Results.

The `certs` field of the `EvidenceBundle` typically contain one or more certification paths rooted in a device manufacturer trust anchor and the end entity certificate being on the device in question. The end entity certificate is associated with key material that takes on the role of an Attestation Key and is used to sign Evidence originating from the Attester. In some interpretations of the RATS Architecture {{RFC9334}}, the Attestation Key Certificate and its corresponding certificate chain are considered to be Endorsements of the Attestation Key. The `certs` field of the `AttestationResultBundle` behaves similarly but the end entity certificate will correspond to a Verifier.
For the purposes of this specification, a certificate chain provided for the purposes of validating another signed object is not considered to be an Endorsement in and of itself. Here, the term "Endorsement" means a signed object containing data about the target environment which may or may not be accompanied by a certificate chain.


- Evidence and Endorsements are placed into an EvidenceStatement along with an OID to identify its type and optionally a hint to the Relying Party about which Verifier (software package, a microservice or some other service) will be capable of parsing it. A set of EvidenceStatement structures may be grouped together along with the set of CertificateChoice structures needed to validate them to form a EvidenceBundle. See {{sec-evidenceAttr}}.

- Attestation Results are carried in the AttestationResult along with an OID to identify its type. A set of AttestationResult structures may be grouped together to form an AttestationResultBundle. See {{sec-arAttr}}.

A CSR may contain one or more Evidence payloads. For example Evidence
asserting the storage properties of a private key, Evidence
asserting firmware version and other general properties
of the device, Evidence signed using different cryptographic
algorithms, or Endorsements provided by the device manufacturer.
Like-wise, a CSR may also contain one or more Attestation Result payloads.

With these attributes, additional
information is available to an RA or CA, which may be used
to decide whether to issue a certificate and what certificate profile
to apply. The scope of this document is, however,
limited to the conveyance of Evidence, Endorsements, and Attestation Results within CSRs. The exact format of the
Evidence, Endorsements, and Attestation Results being conveyed is out of scope of this document as they are defined in various standard and proprietary specifications.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document re-uses the terms defined in {{RFC9334}} related to remote
attestation. Readers of this document are assumed to be familiar with
the following terms: Evidence, Endorsement, Claim, Attestation Result (AR), Attester,
Verifier, Target Environment, Attesting Environment, Composite Device,
Lead Attester, Attestation Key, and Relying Party (RP).

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
access. Other commonly used terms include Secure Element and Trusted Execution
Environment.

Since this document combines terminology from two domains - Remote Attestation (RATS) and X.509 PKI - it follows a naming convention to avoid ambiguity. RATS terminology is written in uppercase (e.g., Verifier), while X.509/PKI terminology is written in lowercase (e.g., certification authority (CA)). This distinction clarifies terms that exist in both domains; for instance, a Verifier refers to the RATS entity that processes Evidence, whereas a verifier refers to the PKI entity that validates certificates.
This convention is distinct from camel-case identifiers like "EvidenceStatement", which denote ASN.1 types.

# Architecture {#architecture}

{{fig-arch-background}} shows the high-level communication pattern of the RATS
background check model where the Attester transmits the Evidence in the
CSR to the registration authority (RA) and the certification authority (CA),
which is subsequently forwarded to the Verifier.
The Verifier appraises the received Evidence and computes an Attestation
Result, which is then processed by the RA/CA prior to the certificate
issuance.
The RA and CA are depicted as separate entities with the RA
consuming the Attestation Results and deciding whether or not to forward
the certificate request to the CA.
In some deployments they are co-located roles.
In other deployments, the RA uses a proprietary interface into the CA.
In either case,
communication between RA and CA is out-of-scope, they can be conceptualized
as a single Relying Party entity for the purposes of this specification.
This diagram overlays PKI entities with RATS roles in parentheses.


~~~ aasvg
                            .-----------------.
                            |                 | Compare Evidence
                            |    (Verifier)   | against Appraisal
                            |                 | Policy
                            '------------+----'
                                  ^      |
                       Evidence / |      | Attestation
                    Endorsements  |      | Result
                                  |      v
  .------------.               .--|--------------.       .-----.
  |            +-------------->|----'            |------>|     |
  | end        | Evidence /    | registration    |       | CA  |
  | entity     | Endorsements  | authority (RA)  |       |     |
  |            | in CSR        |                 |       |     |
  | (Attester) |               | (Relying Party) |       |     |
  '------------'               '-----------------'       '-----'
~~~
{: #fig-arch-background title="Example data flow demonstrating the architecture with Background Check Model."}


In addition to the background-check model, the RATS architecture also
defines the passport model, as described in {{Section 5.2 of RFC9334}}.
In the passport model, the Attester transmits Evidence directly to the
Verifier to obtain an Attestation Result, which is subsequently forwarded
to the Relying Party.


~~~ aasvg
   Evidence /
   Endorsements           .-----------------.
   +--------------------->|                 | Compare Evidence /
   |                      |   (Verifier)    | Endorsements
   |     +----------------|                 | against Appraisal
   |     |                '-----------------' Policy
   |     | Attestation
   |     | Result
   |     v
.--------|---.             .-----------------.              .------.
|        +-->+------------>| registration    |------------->|      |
| end        | Attestation | authority (RA)  |              |  CA  |
| entity     | Result in   |                 |              |      |
| (Attester) | CSR         | (Relying Party) |              |      |
'------------'             '-----------------'              '------'
~~~
{: #fig-arch-passport title="Example data flow demonstrating the architecture with Passport Model."}


The choice of model depends on various factors. For instance, the
background-check model is preferred when direct real-time interaction
between the Attester and the Verifier is not feasible.

The interface
by which the Relying Party passes Evidence and Endorsements to the Verifier and receives back
Attestation Results may be proprietary or standardized, but in any case is
out-of-scope for this document. Like-wise, the interface between the Attester
and the Verifier used in the passport model is also out-of-scope for this
document.






RFC 9334 {{RFC9334}} discusses different security and privacy aspects that need to be
considered when developing and deploying a remote attestation solution. For example,
Evidence may need to be protected against replay and {{Section 10 of RFC9334}} lists
approach for offering freshness. There are also concerns about the exposure of
persistent identifiers by utilizing attestation technology, which are discussed in
{{Section 11 of RFC9334}}. Finally, the keying material used by the Attester needs to
be protected against unauthorized access, and against signing arbitrary content that
originated from outside the device. This aspect is described in {{Section 12 of RFC9334}}.
Most of these aspects are, however, outside the scope of this specification but relevant
for use with a given attestation technology.

The focus of this specification is on the transport of Evidence, Endorsements, and Attestation Results
from the Attester to the Relying Party via existing CSR messages.

# Information Model

## Model for Evidence and Endorsements in CSR

To support a number of different use cases for the transmission of
Evidence, Endorsements and certificate chains needed to validate them in a CSR the structure
shown in {{fig-info-model}} is used.

On a high-level, the structure is composed as follows:
A PKCS#10 attribute or a CRMF extension contains one
EvidenceBundle structure. The EvidenceBundle contains one or more
EvidenceStatement structures as well as one or more
CertificateChoices which enable to carry various format of
certificates. For the purpose of conveyance within these structures,
Evidence and Endorsements are considered interchangeable since they are both signed data objects with a certificate chain that needs to be validated by a Verifier, so for the
remainder of this document, the term "Evidence" will be used to refer to both types of RATS conceptual messages.

Note: Since an extension must only be included once in a certificate
see {{Section 4.2 of RFC5280}}, this PKCS#10 attribute
or the CRMF extension MUST only be included once in a CSR.

~~~ aasvg
 +-------------------+
 | PKCS#10 Attribute |
 |       or          |
 | CRMF Extension    |
 +--------+----------+
       1  ^
          |                1..n  +-------------------------+
          |        +------------>| CertificateChoices      |
          |        |             +-------------------------+
          |        |             | Certificate OR          |
          |        |             | OtherCertificateFormat  |
       1  |        |             +-------------------------+
          v      1 v
 +--------------------+ 1         1..n  +-------------------+
 |  EvidenceBundle    |<--------------->| EvidenceStatement |
 +--------------------+                 +-------------------+
                                        | Type              |
                                        | Statement         |
                                        | Hint              |
                                        +-------------------+
~~~
{: #fig-info-model title="Information Model for CSR Evidence Conveyance."}

A conformant implementation of an entity processing the CSR structures MUST be prepared
to use certificates found in the EvidenceBundle structure to build a certification
path to validate any EvidenceStatement.
The following use cases are supported, as described in the sub-sections below.

### Case 1 - Evidence Bundle without Certificate Chain

A single Attester, which only distributes Evidence without an attached certificate chain.
In the use case, the Verifier is assumed to be in possession of the certificate chain already
or the Verifier directly trusts the Attestation Key and therefore no certificate chain needs
to be conveyed in the CSR.

As a result, one EvidenceBundle is included in a CSR that contains a single EvidenceStatement
without the CertificateChoices structure. {{fig-single-attester}} shows this use case.

~~~ aasvg
  +--------------------+
  |  EvidenceBundle    |
  +....................+
  | EvidenceStatement  |
  +--------------------+
~~~
{: #fig-single-attester title="Case 1: Evidence Bundle without Certificate Chain."}

### Case 2 - Evidence Bundle with Certificate Chain

A single Attester, which shares Evidence together with a certificate chain, is
shown in {{fig-single-attester-with-path}}. The CSR conveys an EvidenceBundle
with a single EvidenceStatement and a CertificateChoices structure.

~~~ aasvg
 +-------------------------+
 |  EvidenceBundle         |
 +.........................+
 | EvidenceStatement       |
 | CertificateChoices      |
 +-------------------------+
~~~
{: #fig-single-attester-with-path title="Case 2: Single Evidence Bundle with Certificate Chain."}

### Case 3 - Evidence Bundles with Multiple Evidence Statements and Complete Certificate Chains

In a Composite Device, which contains multiple Attesters, a collection of Evidence
statements is obtained. In this use case, each Attester returns its Evidence together with a
certificate chain. As a result, multiple EvidenceStatement structures and the corresponding CertificateChoices structure with the
certification chains as provided by the Attester, are included in the CSR.
This approach does not require any processing capabilities
by a Lead Attester since the information is merely forwarded. {{fig-multiple-attesters}}
shows this use case.

~~~ aasvg
  +-------------------------+
  |  EvidenceBundle         |
  +.........................+
  | EvidenceStatement (1)   | Provided by Attester 1
  | EvidenceStatement (2)   | Provided by Attester 2
  | CertificateChoices      | Certificates provided by Attester 1 and 2
  +-------------------------+
~~~
{: #fig-multiple-attesters title="Case 3: Multiple Evidence Structures each with Complete Certificate Chains."}


## Model for Attestation Result in CSR

{{fig-info-model-ar}} illustrates the information model for transmitting
Attestation Results as a PKCS#10 attribute or a CRMF extension. This
structure includes a single AttestationResultBundle, which in turn comprises
one or more AttestationResult structures.

~~~ aasvg
+-------------------+
| PKCS#10 Attribute |
|       or          |
| CRMF Extension    |
+-------------------+
      1  ^                        +-------------------+
         |                 1..n   | AttestationResult |
         |         +------------->+-------------------+
         |         |              | Type              |
         |         |              | Result            |
         |         |              |                   |
      1  |         |              +-------------------+
         v       1 v
+-------------------------+
| AttestationResultBundle |
+-------------------------+
~~~
{: #fig-info-model-ar title="Information Model for CSR Attestation Result Conveyance."}

A Relying Party receiving a CSR containing an Attestation Result MUST use the Type information
to parse the content. The Attestation Result encoding MUST provide information for the Relying
Party to determine the Verifier, who created and protected the Attestation Result against modifications.

# ASN.1 Elements for Evidence in CSR

##  Object Identifiers

This document references `id-pkix` and `id-aa`, both defined in {{!RFC5911}} and {{RFC5912}}.

## Evidence Attribute and Extension {#sec-evidenceAttr}

By definition, attributes within a PKCS#10 CSR are
typed as ATTRIBUTE and within a CRMF CSR are typed as EXTENSION.
This attribute definition contains one
Evidence bundle of type `EvidenceBundle` containing
one or more Evidence statements of a type `EvidenceStatement` along with
optional certificates for certification path building.
This structure enables different Evidence statements to share a
certification path without duplicating it in the attribute.

~~~
EVIDENCE-STATEMENT ::= TYPE-IDENTIFIER

EvidenceStatementSet EVIDENCE-STATEMENT ::= {
   ... -- None defined in this document --
}
~~~
{: #code-EvidenceStatementSet title="Definition of EvidenceStatementSet"}

The expression illustrated in {{code-EvidenceStatementSet}} maps ASN.1 Types
for Evidence Statements to the OIDs
that identify them. These mappings are used to construct
or parse EvidenceStatements. Evidence Statements are typically
defined in other IETF standards, other standards bodies,
or vendor proprietary formats along with corresponding OIDs that identify them.

This list is left unconstrained in this document. However, implementers can
populate it with the formats that they wish to support.

~~~
EvidenceStatement ::= SEQUENCE {
   type   EVIDENCE-STATEMENT.&id({EvidenceStatementSet}),
   stmt   EVIDENCE-STATEMENT.&Type({EvidenceStatementSet}{@type}),
   hint   IA5String OPTIONAL
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

To simplify the task for the Relying Party to select an appropriate Verifier
an optional field, the hint, is available in the EvidenceStatement structure,
as shown in {{code-EvidenceStatement}}. An Attester MAY include the hint to
the EvidenceStatement and it MAY be processed by the Relying Party. The
Relying Party MAY decide not to trust the information embedded in the hint
or policy MAY override any information provided by the Attester via this hint.

When the Attester populates the hint, it MUST contain a server name which
uniquely identifies a Verifier. Server names are ASCII strings that
contain a hostname and optional port, where the port is implied to be
"443" if missing.  The names use the format of the authority portion
of a URI as defined in Section 3.2 of {{RFC3986}}. The names MUST NOT
include a "userinfo" portion of an authority.  For example, a valid
server name might be "verifier.example.com" or
"verifier.example.com:8443", but not "verifier@example.com".

Relying Parties SHOULD NOT connect to a host name provided in the hint,
especially if the verifier has no previous trust relationship with that
host name, instead this SHOULD be used only as a lookup string for
determining between a list of Verifiers that the Relying Party is
pre-configured to use.

In a typical usage scenario, the Relying Party is pre-configured with
a list of trusted Verifiers and the corresponding hint values can be used to look
up appropriate Verifier. The Relying Party is also configured with a trust
anchor for each Verifier, which allows the Verifier to validate the signature
protecting the Attestation Result. Tricking a Relying Party into interacting
with an unknown and untrusted Verifier must be avoided.

~~~
EvidenceBundle ::= SEQUENCE {
   evidences SEQUENCE SIZE (1..MAX) OF EvidenceStatement,
   certs SEQUENCE SIZE (1..MAX) OF CertificateChoices OPTIONAL,
      -- CertificateChoices MUST only contain certificate or other,
      -- see Section 10.2.2 of [RFC5652]
}
~~~

The CertificateChoices structure defined in {{RFC6268}} allows for carrying certificates in the default X.509 {{RFC5280}} format, or in other non-X.509 certificate formats. CertificateChoices MUST only contain certificate or other. CertificateChoices MUST NOT contain extendedCertificate, v1AttrCert, or v2AttrCert. Note that for non-ASN.1 certificate formats, the CertificateChoices MUST use `other [3]` with an `OtherCertificateFormat.Type` of `OCTET STRING`, and then can carry any binary data.

The `certs` field contains a set of certificates that
is intended to validate the contents of an Evidence statement
contained in `evidences`, if required. For each Evidence statement, the set of certificates SHOULD contain
the certificate that contains the public key needed to directly validate the
Evidence statement, unless the signing key is expected to be known to the Verifier or is embedded within the statement. Additional certificates MAY be provided, for example, to chain the
Evidence signer key back to an agreed upon trust anchor. No specific order of the certificates in `certs` SHOULD be expected because certificates contained in `certs` may be needed to validate different Evidence statements.

This specification places no restriction on mixing certificate types within the `certs` field. For example a non-X.509 Evidence signer certificate MAY chain to a trust anchor via a chain of X.509 certificates. It is up to the Attester and its Verifier to agree on supported certificate formats.

~~~
id-aa-evidence OBJECT IDENTIFIER ::= { id-aa 59 }

-- For PKCS#10
attr-evidence ATTRIBUTE ::= {
  TYPE EvidenceBundle
  COUNTS MAX 1
  IDENTIFIED BY id-aa-evidence
}

-- For CRMF
ext-evidence EXTENSION ::= {
  SYNTAX EvidenceBundle
  IDENTIFIED BY id-aa-evidence
}
~~~
{: #code-extensions title="Definitions of CSR attribute and extension"}

The Extension variant illustrated in {{code-extensions}} is intended only for use within CRMF CSRs and is NOT RECOMMENDED to be used within X.509 certificates due to the privacy implications of publishing Evidence about the end entity's hardware environment. See {{sec-con-publishing-x509}} for more discussion.

By the nature of the PKIX ASN.1 classes {{RFC5912}}, there are multiple ways to convey multiple Evidence statements: by including multiple copies of `attr-evidence` or `ext-evidence`, multiple values within the attribute or extension, and finally, by including multiple `EvidenceStatement` structures within an `EvidenceBundle`. The latter is the preferred way to carry multiple Evidence statements. Implementations MUST NOT place multiple copies of `attr-evidence` into a PKCS#10 CSR due to the `COUNTS MAX 1` declaration. In a CRMF CSR, implementers SHOULD NOT place multiple copies of `ext-evidence`.


# ASN.1 Elements for Attestation Result in CSR

When operating according to the RATS Passport Model, as depicted in {{fig-arch-passport}}, the CSR sent to the CA / RA will contain Attestation Results in place of Evidence or Endorsements. In order to clearly differentiate Background Check and Passport Model use cases, this section registers a different top-level CSR Attribute (PKCS#10) and Extension (CRMF) for carrying Attestation Results, which are syntactically identical to those for carrying Evidence and Endorsements.

##  Object Identifiers

This document defines the OID depicted in {{code-ar-oid}} as an additional CSR Attribute (PKCS#10) or Extension (CRMF) to carry Attestation Results in a CSR.

~~~
-- OID for Attestation Result types
id-aa-ar OBJECT IDENTIFIER ::= { id-aa (TBD2) }
~~~
{: #code-ar-oid title="New OID for PKIX Attestation Result Formats"}

## Attestation Result Attribute and Extension {#sec-arAttr}

By definition, attributes within a PKCS#10 CSR are
typed as ATTRIBUTE and within a CRMF CSR are typed as EXTENSION.
This attribute definition contains one AttestationResultBundle structure.

~~~
ATTESTATION-RESULT ::= TYPE-IDENTIFIER

AttestationResultSet ATTESTATION-RESULT ::= {
   ... -- None defined in this document --
}
~~~
{: #code-AttestationResultSet title="Definition of AttestationResultSet"}

The expression illustrated in {{code-AttestationResultSet}}
maps ASN.1 Types for Attestation Result to the OIDs that identify them. These
mappings are used to construct or parse AttestationResults. Attestation Results
are defined in other IETF standards (see {{?I-D.ietf-rats-ar4si}}),
other standards bodies, or vendor proprietary formats along with corresponding
OIDs that identify them.

This list is left unconstrained in this document. However, implementers can
populate it with the formats that they wish to support.

~~~
AttestationResult ::= SEQUENCE {
   type   ATTESTATION-RESULT.&id({AttestationResultSet}),
   stmt   ATTESTATION-RESULT.&Type({AttestationResultSet}{@type}),
}
~~~
{: #code-AttestationResult title="Definition of AttestationResult"}

In {{code-AttestationResult}}, type is an OID that indicates the format of the
value of stmt.

~~~
AttestationResultBundle ::= SEQUENCE {
   results SEQUENCE SIZE (1..MAX) OF AttestationResult,
   certs SEQUENCE SIZE (1..MAX) OF CertificateChoices OPTIONAL,
      -- CertificateChoices MUST only contain certificate or other,
      -- see Section 10.2.2 of [RFC5652]
}
~~~

~~~
-- For PKCS#10
attr-ar ATTRIBUTE ::= {
  TYPE AttestationResultBundle
  COUNTS MAX 1
  IDENTIFIED BY id-aa-ar
}

-- For CRMF
ext-ar EXTENSION ::= {
  SYNTAX AttestationResultBundle
  IDENTIFIED BY id-aa-ar
}
~~~
{: #code-extensions-ar title="Definitions of CSR attribute and extension"}

# Implementation Considerations

## Is the CSR constructed inside or outside the Attester?

This specification is applicable both in cases where a CSR
is constructed internally or externally to the Attesting Environment, from the
point of view of the calling application. This section is particularly
applicable to the background check model.

Cases where the CSR is generated internally to the Attesting Environment
are straightforward: the hardware security module (HSM) generates and embeds
the Evidence and the corresponding certification paths when constructing the CSR.

Cases where the CSR is generated externally might require extra communication
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

## Separation of RA and CA roles with respect to Attestation Results {#sec-impl-ar}

As described in {{architecture}}, CSRs MAY contain either Evidence or Attestation Results (AR),
and also the registration authority (RA) and certification authority (CA) MAY be conceptualized as
a single Relying Party entity, or as separate entities. There are some implications here worth discussion.

In many cases, the Evidence contained within a CSR is intended to be consumed by the RA and not
to be placed into the issued certificate.
In some RA / CA architectures, it MAY be appropriate for the RA to "consume" the Evidence
and remove it from the CSR, re-signing the CSR with an RA signing key. A CRMF CSR also allows the RA
to indicate that it verified the CSR without the need to re-signing the CSR.

In any case where the RA and CA roles are separated, and Evidence is evaluated and consumed by the RA,
the RA does at least implicitly produce Attestation Results as defined in the RATS Architecture [RFC9334].
For example, the decision to reject the Evidence and fail back to the client, or to accept the Evidence and
forward a request to the CA could be viewed as a boolean Attestation Result.
Similarly, if acceptance or rejection of the Evidence controls the presence or absence of a certain policy OID
or other extension in the issued certificate, this could also be viewed as an Attestation Result.

Alternatively, the RA MAY place explicit Attestation Results into its request to the CA; either for consumption
by the CA or for inclusion in the issued certificate.
The exact mechanisms for doing this are out-of-scope for this document, but are areas for implementation
consideration and potential future standardization work.

# IANA Considerations

IANA is requested to open two new registries, allocate a value
from the "SMI Security for PKIX Module Identifier" registry for the
included ASN.1 module, and allocate values from "SMI Security for
S/MIME Attributes" to identify two attributes defined within.

##  Module Registration - SMI Security for PKIX Module Identifier

IANA is asked to register the following within the registry id-mod
SMI Security for PKIX Module Identifier (1.3.6.1.5.5.7.0).

-  Decimal: IANA Assigned - **Replace TBDMOD**
-  Description: CSR-ATTESTATION-2023 - id-mod-pkix-attest-01
-  References: This Document

##  Object Identifier Registrations - SMI Security for S/MIME Attributes

IANA is asked to register the following within the registry id-aa
SMI Security for S/MIME Attributes (1.2.840.113549.1.9.16.2).

- Evidence Statement
- Decimal: IANA Assigned - This was early-allocated as `59` so that we could generate the sample data.
- Description: id-aa-evidence
- References: This Document

- Attestation Result
- Decimal: IANA Assigned - - **Replace TBD2**
- Description: id-aa-ar
- References: This Document

## Attestation Evidence OID Registry

IANA is asked to create a registry that helps developers to find
OID/Evidence mappings that may be encountered in the wild, as well as
a link to their specification document.
This registry should follow the rules for
"Specification Required" as laid out in {{RFC5226}}.

Each row corresponds to an OID and ASN.1 type that could appear in a `EvidenceStatement` or `AttestationResult`, with references for where to find the full specification.

Registration requests should be formatted as per
the registration template below, and receive a three-week review period on
the [spasm] mailing list, with the advice of one or more Designated
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

- Type: The ASN.1 type corresponding to the given OID.

- Description: Brief description of the use of the Evidence and the
registration of the OID.

- Reference(s): Reference to the document or documents that register
the OID and define the ASN.1 type for use with a specific attestation technology, preferably
including URIs that can be used to retrieve copies of the documents.
An indication of the relevant sections may also be included but is not
required.

- Change Controller: The entity that controls the listed data format.
For data formats specified in Standards Track RFCs, list the "IESG".
For others, give the name of the responsible party.
This does not necessarily have to be a standards body, for example
in the case of proprietary data formats the Reference may be to a company or a
publicly-available reference implementation.  In most cases the
third party requesting registration in this registry will also be the
party that registered the OID. As the intention is for this registry to be a
helpful reference, rather than a normative list, a fair amount of
discretion is left to the Designated Expert.

### Initial Registry Contents

The initial registry contents is shown in the table below.
It lists entries for several evidence encoding OIDs including an entry for the Conceptual Message Wrapper (CMW) {{I-D.ietf-rats-msg-wrap}}.

* CMW
  * OID: 1 3 6 1 5 5 7 1 35
  * Type: CMW
  * Description: id-pe-cmw
  * Reference(s): {{I-D.ietf-rats-msg-wrap}}
  * Change Controller: IETF

The current registry values can be retrieved from the IANA online website.

[spasm]: mailto:spasm@ietf.org

# Security Considerations

In the RATS architecture, when Evidence or an Attestation Result is presented to a Relying Party (RP), the RP may learn detailed information about the Attester unless that information has been redacted or encrypted. Consequently, a certain amount of trust must be placed in the RP, which raises potential privacy concerns because an RP could be used to track devices. This observation is noted in Section 11 of {{RFC9334}}.

In the RATS architecture, RPs are typically application services that consume remote attestation, rather than PKI-style RAs or CAs. Devices already place substantial trust in RA/CA infrastructure, so additional information disclosed through remote attestation to these entities is generally less sensitive than disclosure to application services. The issue of CAs embedding Evidence into X.509 certificates is discussed in {{sec-con-publishing-x509}}.

These privacy risks can be mitigated using several approaches, including:

- Shared Attestation Keys: A manufacturer may provision all devices in a product family with the same attestation key. This enables anonymity by making devices indistinguishable from one another, but it also prevents revocation of a single device's key if compromised. To preserve privacy in such cases, Evidence must avoid embedding uniquely identifying information, as this would negate the benefits of shared keys.

- Per-Use Attestation Keys: Devices may be designed to dynamically generate distinct attestation keys (and request the corresponding certificates) for each use case, device, or session. This is analogous to the Privacy CA model, in which a device is initially provisioned with an attestation key and certificate; then, in conjunction with a privacy-preserving CA, it can obtain unique keys and certificates as needed. This strategy reduces the potential for tracking while maintaining strong security assurances. This is the model described in this document.

- Anonymous Attestation Mechanisms: Direct Anonymous Attestation (DAA) and related cryptographic schemes enable devices to produce attestation signatures that are verifiable against a root key, but unlinkable across different uses. This prevents a verifier from using repeated attestations with the same key as a global correlation handle to track devices. {{I-D.ietf-rats-daa}} extends the RATS architecture with such a DAA scheme, thereby enhancing privacy.

## Background Check Model Security Considerations

A PKCS#10 or CRMF certification request typically consists of a
distinguished name, a public key, and optionally a set of attributes,
collectively signed by the entity requesting certification.
In general, because an Attestation Key is intended solely for signing Evidence,
 the private key used to sign a CSR SHOULD be distinct from the
Attestation Key used to sign Evidence about the Target
 Environment. Exceptions MAY be allowed when CSRs and Evidence are both part of the process
of bootstrapping the Attestation Key.

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
the Verifier and to the Relying Party (PKI RA/CA) to place as much or
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

## Freshness for the Background Check Model

Evidence generated by an Attester generally needs to be fresh in order to provide
value to the Verifier since the configuration on the device may change
over time. {{Section 10 of RFC9334}} discusses different approaches for
providing freshness, including a nonce-based approach, the use of timestamps
and an epoch-based technique. The use of nonces requires that nonce to be provided by
the Relying Party in some protocol step prior to Evidence and CSR generation,
and the use of timestamps requires synchronized clocks which cannot be
guaranteed in all operating environments. Epochs also require an out-of-band
communication channel.
This document leaves the exchange of nonces and other freshness data to
certificate management protocols, see {{I-D.ietf-lamps-attestation-freshness}}.
Developers, operators, and designers of protocols, which embed
Evidence-carrying-CSRs, MUST consider what notion of freshness is
appropriate and available in-context; thus the issue of freshness is
left up to the discretion of protocol designers and implementers.

In the case of hardware security modules (HSM), the
semantics of "freshness" are somewhat ambiguous in the context
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

Note: Freshness is also a concern for remote attestation in the passport model; however, the protocol between the Attester and the Verifier lies outside the scope of this specification.

## Publishing Evidence in an X.509 Extension {#sec-con-publishing-x509}

This document specifies an Extension for carrying Evidence in a PKCS#10 or CRMF certificate signing request (CSR), but it is intentionally NOT RECOMMENDED for a CA to copy the attr-evidence for PKCS#10 or ext-evidence extension for CRMF into the published certificate.
The reason for this is that certificates are considered public information and the Evidence might contain detailed information about hardware and patch levels of the device on which the private key resides.
The certificate requester has consented to sharing this detailed device information with the CA but might not consent to having these details published.
These privacy considerations are beyond the scope of this document and may require additional signaling mechanisms in the CSR to prevent unintended publication of sensitive information, so we leave it as "NOT RECOMMENDED". Often, the correct layer at which to address this is either in certificate profiles, a Certificate Practice Statement (CPS), or in the protocol or application that carries the CSR to the RA/CA where a flag can be added indicating whether the RA/CA should consider the evidence to be public or private.

## Type OID and Verifier Hint

The `EvidenceStatement` includes both a `type` OID and a `hint` field with which the Attester can provide information to the Relying Party about which Verifier to invoke to parse a given piece of Evidence.
Care should be taken when processing these data since at the time they are used, they are not yet verified. In fact, they are protected by the CSR signature but not by the signature from the Attester and so could be maliciously replaced in some cases.
The authors' intent is that the `type` OID and `hint` will allow an RP to select between Verifier with which it has pre-established trust relationships. The RP MUST NOT blindly make network calls to unknown domain names and trust the results.
Implementers should also be cautious around `type` OID or `hint` values that cause a short-circuit in the verification logic, such as `None`, `Null`, or similar values that could cause the Evidence to appear to be valid when in fact it was not properly checked.

## Additional Security Considerations

In addition to the security considerations listed here, implementers should be familiar with the security considerations of the specifications on which this RFC depends: PKCS#10 {{RFC2986}}, CRMF {{RFC4211}}, as well as general security concepts relating to remote attestation; many of these concepts are discussed in {{Section 6 of RFC9334}}, {{Section 7 of RFC9334}}, {{Section 9 of RFC9334}}, {{Section 11 of RFC9334}}, and {{Section 12 of RFC9334}}. Implementers should also be aware of any security considerations relating to the specific Evidence and Attestation Result formats being carried within the CSR.

--- back


# Examples

This section provides an example that conveys an Arm Platform Security Architecture token,
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

As an example of how to populate EvidenceStatementSet, implementing the CMW and PSA Evidence types would result in the following EvidenceStatementSet definition:

~~~
EvidenceStatementSet EVIDENCE-STATEMENT ::= {
  --- ConceptualMessageWrapper
  { CMW IDENTIFIED BY id-pe-cmw },
  ...,

  --- PSA
  { OCTET STRING IDENTIFIED BY { 1 3 6 1 5 5 7 1 99 } }
}
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
EvidenceBundle
   +
   |
   + Evidences
   |
   +---->  EvidenceStatement
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

## Confidential Compute Architecture (CCA) Platform Token in CSR

The Confidential Compute Architecture (CCA) Platform Token is described in
{{I-D.ffm-rats-cca-token}} and is also based on the EAT format.  Although the
full CCA attestation is composed of Realm and Platform Evidence, for the purposes
of this example only the Platform token is provided.

~~~
EvidenceBundle
   +
   |
   + Evidences
   |
   +---->  EvidenceStatement
        +
        |
        +-> type: OID for CCA Platform Attestation Token
        |         1 3 6 1 5 5 7 1 TBD
        |
        +-> stmt: CCA Platform Token
~~~

Although the CCA Platform Token follows the EAT/CMW format, it is untagged.
This is because the encoding can be discerned in the CSR based on the OID alone.
The untagged token based on a sample claim set is provided below:

~~~
{::include-fold sampledata/cca.diag}
~~~

Realm evidence can be included in a CMW bundle, similar to the PSA token.
In this case, the CSR is constructed as follows:

~~~
EvidenceBundle
   +
   |
   + Evidences
   |
   +---->  EvidenceStatement
        +
        |
        +-> type: OID for CMW Collection
        |         1 3 6 1 5 5 7 1 TBD
        |
        +-> stmt: Realm Token/Platform Token CMW Collection or
                         Realm Claim Set/Platform Token CMW Collection
~~~

# ASN.1 Module

~~~
{::include-fold CSR-ATTESTATION-2025.asn}
~~~

## TCG DICE Example in ASN.1

This section gives an example of extending the ASN.1 module above to carry an existing ASN.1-based Evidence Statement.
The example used is the Trusted Computing Group DICE Attestation Conceptual Message Wrapper, as defined in {{TCGDICE1.2}}.

~~~
{::include-fold CSR-ATTESTATION-WITH-DICE-CMW.asn}
~~~

## TCG DICE TcbInfo Example in CSR

This section gives an example of extending the ASN.1 module above to carry an existing ASN.1-based evidence statement.
The example used is the Trusted Computing Group DiceTcbInfo, as defined in {{TCGDICE1.2}}.

~~~
{::include-fold CSR-ATTESTATION-WITH-DiceTcbInfo.txt}
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
