---
title: "Use of Remote Attestation with Certificate Signing Requests"
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
 - CFMF
 - Attestation
 - Evidence
 - Certificate Signing Requests
venue:
#  group: LAMPS
#  type: Working Group
#  mail: spasm@ietf.org
#  arch: https://datatracker.ietf.org/wg/lamps/about/
  github: "lamps-wg/csr-attestation"
  latest: "https://lamps-wg.github.io/csr-attestation/draft-ounsworth-csr-attestation.html"

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
  - name: Henk Birkholz
    org: Fraunhofer SIT
    abbrev: Fraunhofer SIT
    email: henk.birkholz@sit.fraunhofer.de
    street: Rheinstrasse 75
    code: '64295'
    city: Darmstadt
    country: Germany

normative:
    RFC9334:
    RFC5912:
    RFC4211:

informative:
  RFC2986:
  I-D.tschofenig-rats-psa-token:
  TPM20:
    author:
      org: Trusted Computing Group
    title: Trusted Platform Module Library Specification, Family 2.0, Level 00, Revision 01.59
    date: November 2019
    target: https://trustedcomputinggroup.org/resource/tpm-library-specification/
  CSBR:
    author:
      org: CA/Browser Forum
    title: Baseline Requirements for Code-Signing Certificates, v.3.3
    date: June 2023
    target: https://cabforum.org/wp-content/uploads/Baseline-Requirements-for-the-Issuance-and-Management-of-Code-Signing.v3.3.pdf

--- abstract

A client requesting a certificate from a Certification Authority (CA) may wish to offer believable claims about the protections afforded to the corresponding private key, such as whether the private key resides on a hardware security model or trusted platform module, and the protection capabilities provided by the hardware module.
Including this evidence along with the certificate request can help to improve the assessment of the security posture for the private key, and suitability of the submitted key to the requested certificate profile.
These evidence claims can include information about the hardware component's manufacturer, the version of installed or running firmware, the version of software installed or running in layers above the firmware, or the presence of hardware components providing specific protection capabilities or shielded locations (e.g., to protect keys).
Producing, conveying, and appraising such believable claims is enabled via remote attestation procedures where the device holding the private key takes on the role of an attester and produces evidence that is made available to remote parties in a cryptographically secured way.
This document describes two new extensions to encode evidence produced by an attester
for inclusion in PKCS#10 or CRMF certificate signing requests: an ASN.1 Attribute or Extension definition to convey a cryptographically-signed evidence statement to a Registration Authority or to a Certification Authority, and an ASN.1 Attribute or Extension to carry any certificates necessary for validating the cryptographically-signed evidence statement.

--- middle

# Introduction

When requesting a certificate from a Certification Authority (CA), a PKI end entity may wish to include Evidence of the security properties of its environments in which the private keys are stored in that request.
This Evidence can be appraised by authoritative entities, such as a Registration Authority (RA) or a CA, or associated trusted Verifiers as part of validating an incoming certificate request against given certificate policies.
This specification defines an attribute and an extension that allow for conveyance of Evidence in Certificate Signing Requests (CSRs) in either PKCS#10 {{RFC2986}} or Certificate Request Message Format (CRMF) {{RFC4211}} payloads.

As outlined in the RATS Architecture {{RFC9334}}, an Attester (typically
a device) produces a signed collection of Claims that constitutes Evidence about its running environment.
While the term "attestation" is not defined in RFC 9334, it was later defined in {{?I-D.[ietf-rats-tpm-based-network-device-attest}}, it refers to the activity of producing and appraising remote attestation Evidence.
A Relying Party may consult an Attestation Result produced by a Verifier that has appraised the Evidence in making policy decisions about the trustworthiness of the
target environment being assessed via appraisal of Evidence. {{architecture}} provides the basis to illustrate in this document how the various roles
in the RATS architecture map to a certificate requester and a CA/RA.


At the time of writing, several standard and several proprietary attestation technologies
are in use.
This specification thereby is intended to as technology-agnostic as it is feasible with respect to implemented remote attestation technologies. This specification focuses on (1) the conveyance of Evidence via CSR while making minimal assumptions about content or format of the transported Evidence and (2) the conveyance of sets of certificates used for validation of Evidence.
The certificates typically contain one or more certification paths
rooted in a device manufacture trust anchor and the leaf certificate being
on the device in question; the latter is the Attestation Key that signs the Evidence statement.

This document specifies two ATTRIBUTE/Attribute definitions. The first
Attribute may be used to carry a set of certificates or public keys that
may be required to validate signed Evidence. The second Attribute carries a
structure that may be used to convey Evidence.

A CSR may contain one or more Evidence payloads, for example Evidence
asserting the storage properties of a private key as well Evidence
asserting firmware version and other general properties
of the device, or Evidence signed via certification paths.

With these attributes, additional
information about whether to issue a certificate and what information
to populate into the certificate is available to an RA or CA. The scope of this document is, however,
limited to the conveyance of Evidence within CSR. The exact format of the
Evidence being conveyed is defined in various standard and proprietary
specifications.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document re-uses the terms defined in RFC 9334 related to remote
attestation. Readers of this document are assumed to be familiar with
the following terms: evidence, claim, attestation result, attester,
verifier, and relying party.

# Architecture {#architecture}

{{fig-arch}} shows the high-level communication pattern of the RATS passport
model where the attester transmits the evidence in the CSR to the RA
and the CA. The verifier processes the received evidence and computes
an attestation result, which is then processed by the RA/CA prior to the
certificate issuance.

Note that the verifier is a logical role that may be included in the
RA/CA product. In this case the Relying Party and Verifier collapse into a
single entity. The verifier functionality can, however,
also be kept separate from the RA/CA functionality, such as a utility or
library provided by the device manufacturer. For example,
security concerns may require parsers of evidence formats to be logically
or physically separated from the core CA functionality.

~~~ aasvg
                              .-------------.
                              |             | Compare Evidence
                              |   Verifier  | against
                              |             | policy
                              '--------+----'
                                   ^   |
                          Evidence |   | Attestation
                                   |   | Result
                                   |   v
 .------------.               .----|----------.
 |            +-------------->|----'          | Compare Attestation
 |  Attester  |   Evidence    | Relying       | Result against
 |            |   in CSR      | Party (RA/CA) | policy
 '------------'               '---------------'
~~~
{: #fig-arch title="Architecture"}

As discussed in RFC 9334, different security and privacy aspects need to be
considered. For example, evidence may need to be protected against replay and
Section 10 of RFC 9334 lists approach for offering freshness. There are also
concerns about the exposure of persistent identifiers by utilizing attestation
technology, which are discussed in Section 11 of RFC 9334. Finally, the keying
material used by the attester need to be protected against unauthorized access,
and against signing arbitrary content that originated from outside the device.
This aspect is described in Section 12 of RFC 9334. Most of these aspects are,
however, outside the scope of this specification but relevant for use with a
given attestation technology. The focus of this specification is on the
transport of evidence from the attester to the relying party via existing
certification request messages.

# ASN.1 Elements

##  Object Identifiers

We reference `id-pkix` and `id-aa`, both defined in {{!RFC5912}}.

We define:

~~~
-- Arc for evidence types
id-ata OBJECT IDENTIFIER ::= { id-pkix (TBD1) }
~~~


## Evidence Attribute and Extension

By definition, Attributes within a PKCS#10 CSR are
typed as ATTRIBUTE and within a CRMF CSR are typed as EXTENSION.
This attribute definition contains one or more
evidence statements of a type "EvidenceStatement".

~~~
id-aa-evidenceStatement OBJECT IDENTIFIER ::= { id-aa (TBDAA2) }

-- For PKCS#10
attr-evidence ATTRIBUTE ::= {
  TYPE EvidenceStatement
  IDENTIFIED BY id-aa-evidenceStatement
}

-- For CRMF
ext-evidence EXTENSION ::= {
  TYPE EvidenceStatement
  IDENTIFIED BY id-aa-evidenceStatement
}
~~~

A CSR MAY contain one or more instance of `EvidenceAttribute`.

The Extension version is intended only for use within CRMF CSRs and is NOT RECOMMENDED for use within X.509 certificates due to the privacy implications of publishing evidence about the end entity's hardware environment. See {{security-considerations}} for more discussion.


##  EvidenceStatement

An EvidenceStatement is a simple type-value pair identified by an OID
`type` and containing a value `stmt`.

encoded as
a sequence, of which the type of the "value" field is
controlled by the value of the "type" field, similar to an Attribute
definition.

~~~
EVIDENCE-STATEMENT ::= TYPE-IDENTIFIER

EvidenceStatementSet EVIDENCE-STATEMENT ::= {
   ... -- Empty for now --
}

EvidenceStatement {EVIDENCE-STATEMENT:EvidenceStatementSet} ::= SEQUENCE {
   type   EVIDENCE-STATEMENT.&id({EvidenceStatementSet}),
   stmt   EVIDENCE-STATEMENT.&Type({EvidenceStatementSet}{@type})
}

id-aa-evidenceStatement OBJECT IDENTIFIER ::= { id-aa aa-evidenceStatement(TBDAA2) }

-- For PKCS#10
attr-evidence ATTRIBUTE ::= {
  TYPE EvidenceStatement
  IDENTIFIED BY id-aa-evidenceStatement
}

-- For CRMF
ext-evidence EXTENSION ::= {
  TYPE EvidenceStatement
  IDENTIFIED BY id-aa-evidenceStatement
}
~~~

##  EvidenceCerts

The "EvidenceCertsAttribute" contains a set of certificates that
may be needed to validate the contents of an evidence statement
contained in an evidenceAttribute. The set of certificates should contain
the object that contains the public key needed to directly validate the
EvidenceAttribute.  The remaining elements should chain that data back to
an agreed upon trust anchor used for attestation. No order is implied, it is
the Verifier's responsibility to perform the appropriate certification path
construction.

A CSR MUST contain at zero or one `EvidenceCertsAttribute`. In the case where
the CSR contains multiple instances of `EvidenceAttribute` representing
multiple evidence statements, all necessary certificates MUST be contained in
the same instance of `EvidenceCertsAttribute`.
`EvidenceCertsAttribute` MAY be omitted if there are no certificates to convey, for example if they are already known to the verifier, or if they are contained in the evidence statement.


~~~
id-aa-evidenceChainCerts OBJECT IDENTIFIER ::= { id-aa (TBDAA1) }

-- For PKCS#10
attr-evidenceCerts ATTRIBUTE ::= {
  TYPE SEQUENCE OF CertificateChoice
  COUNTS MAX 1
  IDENTIFIED BY id-aa-evidenceChainCerts
}

-- For CRMF
ext-evidenceCerts EXTENSION ::= {
  TYPE SEQUENCE OF CertificateChoice
  COUNTS MAX 1
  IDENTIFIED BY id-aa-evidenceChainCerts
}
~~~

The Extension version is intended only for use within CRMF CSRs and is NOT RECOMMENDED for use within X.509 certificates due to the privacy implications of publishing evidence about the end entity's hardware environment. See {{security-considerations}} for more discussion.

##  CertificateChoice

This is an ASN.1 CHOICE construct used to represent an encoding of a
broad variety of certificate types.

~~~
CertificateChoice ::=
   CHOICE {
      cert Certificate,
      opaqueCert    [0] IMPLICIT OCTET STRING,
      typedCert     [1] IMPLICIT TypedCert,
      typedFlatCert [2] IMPLICIT TypedFlatCert
   }
~~~

"Certificate" is a standard X.509 certificate that MUST be compliant

with RFC 5280.  Enforcement of this constraint is left to the relying
parties.

"opaqueCert" should be used sparingly as it requires the verifier to implictly know its format.
It is encoded as an OCTET STRING.

"TypedCert" is an ASN.1 construct that has the charateristics of a
certificate, but is not encoded as an X.509 certificate.  The
certType Field (below) indicates how to interpret the certBody field.  While
it is possible to carry any type of data in this structure, it's
intended the content field include data for at least one public key
formatted as a SubjectPublicKeyInfo (see {{RFC5912}}).

~~~
TYPED-CERT ::= TYPE-IDENTIFIER

CertType ::= TYPED-CERT.&id

TypedCert ::= SEQUENCE {
              certType     TYPED-CERT.&id({TypedCertSet}),
              content     TYPED-CERT.&Type ({TypedCertSet}{@certType})
          }

TypedCertSet TYPED-CERT ::= {
             ... -- Empty for now,
             }
~~~

"TypedFlatCert" is a certificate that does not have a valid ASN.1
encoding.
These are often compact or implicit certificates used by smart cards.
certType indicates the format of the data in the
certBody field, and ideally refers to a published specification.

~~~
TypedFlatCert ::= SEQUENCE {
    certType OBJECT IDENTIFIER,
    certBody OCTET STRING
}
~~~

# IANA Considerations

The IANA is requested to open one new registry, allocate a value
from the "SMI Security for PKIX Module Identifier" registry for the
included ASN.1 module, and allocate values from "SMI Security for
S/MIME Attributes" to identify two Attributes defined within.

##  Object Identifier Allocations

###  Module Registration - SMI Security for PKIX Module Identifer

-  Decimal: IANA Assigned - Replace TBDMOD
-  Description: CSR-ATTESTATION-2023 - id-mod-pkix-attest-01
-  References: This Document

###  Object Identifier Registrations - SMI Security for S/MIME Attributes

- Attest Statement

  - Decimal: IANA Assigned - Replace TBDAA2
  - Description: id-aa-evidenceStatement
  - References: This Document

- Attest Certificate Chain

  - Decimal: IANA Assigned - Replace TBDAA1
  - Description: id-aa-evidenceChainCerts
  - References: This Document

###  "SMI Security for PKIX Evidence Statement Formats" Registry

Please open up a registry for evidence Statement Formats within
the SMI-numbers registry, allocating an assignment from id-pkix ("SMI
Security for PKIX" Registry) for the purpose.

-  Decimal: IANA Assigned - replace TBD1
-  Description: id-ata
-  References: This document
-  Initial contents: None
-  Registration Regime: Specification Required.
   Document must specify an EVIDENCE-STATEMENT definition to which this Object Identifier shall be bound.

Columns:

-  Decimal: The subcomponent under id-ata
-  Description: Begins with id-ata
-  References: RFC or other document

# Security Considerations

The evidence communicated in the attributes and
structures defined in this document are meant to be used in
a PKCS#10 or Certificate Signing Request (CSR). It is up to the
verifier and to the relying party (RA/CA) to place as much or
as little trust in this information as dictated by policies.

This document defines the transport of evidence of different formats
in a CSR. Some of these evidence formats are based on standards
while others are proprietary formats. A verifier will need to understand
these formats for matching the received values against policies.

Policies drive the processing of evidence at the verifier:
the Verifier's Appraisal Policy for Evidence will often be specified by the manufacturer of a hardware security module or specified by a regulatory body such as the CA Browser Forum Code-Signing Baseline Requirements {{CSBR}} which specifies certain properties, such as non-exportability, which must be enabled for storing publicly-trusted code-signing keys.

The relying party is ultimately responsible for making a decision of what attestation-related  information in the CSR it will accept. The presence of the attributes
defined in this specification provide the relying party with additional
assurance about attester. Policies used at the verifier and the relying
party are implementation dependent and out of scope for this document.
Whether to require the use of evidence in the CSR is out-of-scope
for this document.

## Freshness

Evidence generated by an attester generally needs to be fresh to provide
value to the verifier since the configuration on the device may change
over time. Section 10 of {{RFC9334}} discusses different approaches for
providing freshness, including a nonce-based approach, the use of timestamps
and an epoch-based technique.  The use of nonces requires an extra message
exchange via the relying party and the use of timestamps requires
synchronized clocks.
Epochs also require (unidirectional) communication.
None of these things are practical when interacting with Hardware Security Modules (HSM).

Additionally, the definition of "fresh" is somewhat ambiguous in the context of CSRs, especially
considering that non-automated certificate enrollments are often asyncronous,
and considering the common practice of re-using the same CSR
for multiple certificate renewals across the lifetime of a key.
"Freshness" typically implies both asserting that the data was generated
at a certain point-in-time, as well as providing non-replayability.
Certain use cases may have special properties impacting the freshness requirements. For example, HSMs are typically designed to not allow downgrade of private key storage
properties; for example if a given key was asserted at time T to have been
generated inside the hardware boundary and to be non-exportable,
then it can be assumed that those properties of that key will continue
to hold into the future.
Developers, operators, and designers of protocols which embed
evidence-carrying-CSRs need to consider what notion of freshness is
appropriate and available in-context; thus the issue of freshness is
left up to the discretion of protocol designers and implementors.

## Publishing evidence in an X.509 extension

This document specifies and Extension for carrying evidence in a CRMF Certificate Signing Request (CSR), but it is intentionally NOT RECOMMENDED for a CA to copy the ext-evidence or ext-evidenceCerts extensions into the published certificate.
The reason for this is that certificates are considered public information and the evidence might contain detailed information about hardware and patch levels of the device on which the private key resides.
The certificate requester has consented to sharing this detailed device information with the CA but might not consent to having these details published.
These privacy considerations are beyond the scope of this document and may require additional signaling mechanisms in the CSR to prevent unintended publication of sensitive information, so we leave it as "NOT RECOMMENDED".

--- back

# Examples

This section provides two non-normative examples for embedding evidence
in in CSRs. The first example conveys Arm Platform Security Architecture
tokens, which provides claims about the used hardware and software platform,
into the CSR. The second example embeds the TPM v2.0 evidence in the CSR.

##  TPM V2.0 Evidence in CSR

The following example illustrates a CSR with a signed TPM Quote based on
{{TPM20}}. The Platform Configuration Registers (PCRs) are fixed-size
registers in a TPM that record measurements of software and configuration
information and are therefore used to capture the system state. The digests
stored in these registers are then digitially signed with an attestation
key known to the hardware.

Note: The information conveyed in the value field of the EvidenceStatement
structure may contain more information than the signed TPM Quote structure
defined in the TPM v2.0 specification {{TPM20}}, such as plaintext PCR values,
the up-time, the event log, etc. The detailed structure of such
payload is, however, not defined in this document and may be subject to
future standardization work in supplementary documents.

~~~
Certification Request:
    Data:
        Version: 1 (0x0)
        Subject: CN = server.example.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:b9:7c:02:a1:1f:9c:f3:f4:c4:55:3a:d9:3e:26:
                    e8:e5:11:63:84:36:5f:93:a6:99:7d:d7:43:23:0a:
                    4f:c0:a8:40:46:7e:8d:b2:1a:38:19:ff:6a:a7:38:
                    16:06:1e:12:9f:d1:d5:58:55:e6:be:6d:bb:e1:fb:
                    f7:70:a7:5c:c9
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        Attributes:
            EvidenceStatement
               type: TBD2 (identifying use of TPM V2.0)
               value:
                    80:02:00:00:01:99:00:00:00:00:00:00:01:86:00:7e
                    ff:54:43:47:80:18:00:22:00:0b:76:71:0f:61:80:95
                    8d:89:32:38:a6:cc:40:43:02:4a:da:26:d5:ea:11:71
                    99:d7:a5:59:a4:18:54:1e:7b:86:00:0d:30:2e:66:6e
                    6a:37:66:63:39:31:76:62:74:00:00:00:00:00:00:36
                    5b:bc:0b:71:4f:d8:84:90:09:01:42:82:48:a6:46:53
                    98:96:00:00:00:01:00:0b:03:0f:00:00:00:20:49:ce
                    66:9a:aa:7e:52:ff:93:0e:dd:9f:27:97:88:eb:75:cb
                    ad:53:22:e5:ad:2c:9d:44:1e:dd:65:48:6b:88:00:14
                    00:0b:01:00:15:a4:95:8a:0e:af:04:36:be:35:f7:27
                    85:bd:7f:87:46:74:18:e3:67:2f:32:f2:bf:b2:e7:af
                    a1:1b:f5:ca:1a:eb:83:8f:2f:36:71:cd:7c:18:ab:50
                    3d:e6:6e:ab:2e:78:a7:e4:6d:cf:1f:03:e6:46:74:28
                    a7:6c:d6:1e:44:3f:88:89:36:9a:a3:f0:9a:45:07:7e
                    01:5e:4c:97:7d:3f:e2:f7:15:59:96:5f:0e:9a:1c:b3
                    a0:6b:4a:77:a5:c0:e0:93:53:cb:b7:50:59:3d:23:ee
                    5c:31:00:48:6c:0b:1a:b8:04:a4:14:05:a6:63:bc:36
                    aa:7f:b9:aa:1f:19:9e:ee:49:48:08:e1:3a:d6:af:5f
                    d5:eb:96:28:bf:41:3c:89:7a:05:4b:b7:32:a2:fc:e7
                    f6:ad:c7:98:a6:98:99:f6:e9:a4:30:d4:7f:5e:b3:cb
                    d7:cc:76:90:ef:2e:cc:4f:7d:94:ab:33:8c:9d:35:5d
                    d7:57:0b:3c:87:9c:63:89:61:d9:5c:a0:b7:5c:c4:75
                    21:ae:dc:c9:7c:e3:18:a2:b3:f8:15:27:ff:a9:28:2f
                    cb:9b:17:fe:96:04:53:c4:19:0e:bf:51:0e:9d:1c:83
                    49:7e:51:64:03:a1:40:f1:72:8b:74:e3:16:79:af:f1
                    14:a8:5e:44:00:00:01:00:00
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:93:fd:81:03:75:d1:7d:ab:53:6c:a5:19:a7:
        68:3d:d6:e2:39:14:d6:9e:47:24:38:b5:76:db:18:a6:ca:c4:
        8a:02:20:36:be:3d:71:93:5d:05:c3:ac:fa:a8:f3:e5:46:db:
        57:f9:23:ee:93:47:6d:d6:d3:4f:c2:b7:cc:0d:89:71:fe
~~~
{: #fig-example-tpm title="CSR with TPM V2.0"}

## Platform Security Architecture Attestation Token in CSR

The example shown in {{fig-example-psa}} illustrates how the Arm
Platform Security Architecture (PSA) Attestation Token
is conveyed in a CSR. The content of the evidence in this example is re-used
from {{I-D.tschofenig-rats-psa-token}} and contains an Entity Attestation
Token (EAT) digitally signed with an attestation private key.

~~~
Certification Request:
    Data:
        Version: 1 (0x0)
        Subject: CN = server.example.com
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:b9:7c:02:a1:1f:9c:f3:f4:c4:55:3a:d9:3e:26:
                    e8:e5:11:63:84:36:5f:93:a6:99:7d:d7:43:23:0a:
                    4f:c0:a8:40:46:7e:8d:b2:1a:38:19:ff:6a:a7:38:
                    16:06:1e:12:9f:d1:d5:58:55:e6:be:6d:bb:e1:fb:
                    f7:70:a7:5c:c9
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        Attributes:
            EvidenceStatement
               type: TBD1 (referring to the PSA Attestation Token)
               value: d2:84:43:a1:01:26:a0:59:01:3b:aa:19:01:09:78:
                      18:68:74:74:70:3a:2f:2f:61:72:6d:2e:63:6f:6d:
                      2f:70:73:61:2f:32:2e:30:2e:30:19:09:5a:1a:7f:
                      ff:ff:ff:19:09:5b:19:30:00:19:09:5c:58:20:00:
                      00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
                      00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:
                      00:19:09:5d:48:00:00:00:00:00:00:00:00:19:09:
                      5e:73:31:32:33:34:35:36:37:38:39:30:31:32:33:
                      2d:31:32:33:34:35:19:09:5f:81:a2:02:58:20:03:
                      03:03:03:03:03:03:03:03:03:03:03:03:03:03:03:
                      03:03:03:03:03:03:03:03:03:03:03:03:03:03:03:
                      03:05:58:20:04:04:04:04:04:04:04:04:04:04:04:
                      04:04:04:04:04:04:04:04:04:04:04:04:04:04:04:
                      04:04:04:04:04:04:0a:58:20:01:01:01:01:01:01:
                      01:01:01:01:01:01:01:01:01:01:01:01:01:01:01:
                      01:01:01:01:01:01:01:01:01:01:01:19:01:00:58:
                      21:01:02:02:02:02:02:02:02:02:02:02:02:02:02:
                      02:02:02:02:02:02:02:02:02:02:02:02:02:02:02:
                      02:02:02:02:19:09:60:78:2e:68:74:74:70:73:3a:
                      2f:2f:76:65:72:61:69:73:6f:6e:2e:65:78:61:6d:
                      70:6c:65:2f:76:31:2f:63:68:61:6c:6c:65:6e:67:
                      65:2d:72:65:73:70:6f:6e:73:65:58:40:56:f5:0d:
                      13:1f:a8:39:79:ae:06:4e:76:e7:0d:c7:5c:07:0b:
                      6d:99:1a:ec:08:ad:f9:f4:1c:ab:7f:1b:7e:2c:47:
                      f6:7d:ac:a8:bb:49:e3:11:9b:7b:ae:77:ae:c6:c8:
                      91:62:71:3e:0c:c6:d0:e7:32:78:31:e6:7f:32:84:
                      1a
    Signature Algorithm: ecdsa-with-SHA256
    Signature Value:
        30:45:02:21:00:93:fd:81:03:75:d1:7d:ab:53:6c:a5:19:a7:
        68:3d:d6:e2:39:14:d6:9e:47:24:38:b5:76:db:18:a6:ca:c4:
        8a:02:20:36:be:3d:71:93:5d:05:c3:ac:fa:a8:f3:e5:46:db:
        57:f9:23:ee:93:47:6d:d6:d3:4f:c2:b7:cc:0d:89:71:fe
~~~
{: #fig-example-psa title="CSR with embedded PSA Attestation Token"}

The decoded evidence is shown in Appendix A of
{{I-D.tschofenig-rats-psa-token}}, the shown evidence, provides the following
information to an RA/CA:

- Boot seed,
- Firmware measurements,
- Hardware security certification reference,
- Identification of the immutable root of trust implementation, and
- Lifecycle state information.


# ASN.1 Module

~~~
{::include CSR-ATTESTATION-2023.asn}
~~~

# Acknowledgments

This specification is the work of a design team created by the chairs of the
LAMPS working group. The following persons, in no specific order,
contributed to the work: Richard Kettlewell, Chris Trufan, Bruno Couillard,
Jean-Pierre Fiset, Sander Temme, Jethro Beekman, Zsolt Rózsahegyi, Ferenc
Pető, Mike Agrenius Kushner, Tomas Gustavsson, Dieter Bong, Christopher Meyer,
Michael StJohns, Carl Wallace, Michael Ricardson, Tomofumi Okubo, Olivier
Couillard, John Gray, Eric Amador, Johnson Darren, Herman Slatman, Tiru Reddy,
Thomas Fossati, Corey Bonnel, Argenius Kushner, James Hagborg.

We would like to specifically thank Mike StJohns for his work on an earlier
version of this draft.
