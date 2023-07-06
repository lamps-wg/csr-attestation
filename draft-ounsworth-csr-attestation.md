---
title: "Use of Attestation with Certification Signing Requests"
abbrev: "CSR Attestation Attributes"
category: std

docname: draft-ounsworth-csr-attestation-latest
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
 - Attestation
 - Certification Signing Requests
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

normative:
    RFC9334:
    RFC5912:

informative:
  RFC2986:
  I-D.tschofenig-rats-psa-token:
  TPM20:
     author:
        org: Trusted Computing Group
     title: Trusted Platform Module Library Specification, Family 2.0, Level 00, Revision 01.59
     target: https://trustedcomputinggroup.org/resource/tpm-library-specification/
     date: November 2019

--- abstract

Utilizing information from a device or hardware security module about its posture
can help to improve security of the overall system. Information about the manufacturer
of the hardware, the version of the firmware running on this hardware and potentially
about the layers of software above the firmware, the presence of hardware security
functionality to protect keys and many more properties can be made available to remote
parties in a cryptographically secured way. This functionality is accomplished with
attestation technology.

This document describes extensions to encode evidence produced by an attester
for inclusion in PKCS10 certificate signing requests. More specifically, two
new ASN.1 Attribute definitions, and an ASN.1 CLASS definition to convey
attestation information to a Registration Authority or to a Certification
Authority are described.

--- middle

# Introduction

At the time that it is requesting a certificate from a Certification
Authority, a PKI end entity may wish to provide evidence of the security
properties of the environment in which the private key is stored to be verified
by a relying party such as the Registration Authority or the Certificate
Authority. This specification provides a newly defined attestation attribute
for carrying remote attestations in PKCS#10 Certification Requests (CSR) {{RFC2986}}.

As outlined in the RATS Architecture {{RFC9334}}, an Attester (typically
a device) produces a signed collection of Evidence about its running environment,
often refered to as an "attestation". A Relying Party may consult that
attestation in making policy decisions about the trustworthiness of the
entity being attested. {{architecture}} overviews how the various roles
in the RATS Archictecture map to a certificate requester and a CA/RA.

At the time of writing, several standardized and proprietary attestation technologies
are in use. This specification thereby tries to be technology agnostic with
regards to the transport of the produced signed claims.

This document is concerned only about the transport of an attesttation
inside a CSR and makes minimal assumptions about its content or format.
We assume that an attestation can be broken into the following components:

1. A set of certificates typically containing one or more certificate chains
   rooted in a device manufacture trust anchor and the leaf certificate being
   on the device in question.
1. An attestation statement containing Evidence.

This document creates two ATTRIBUTE/Attribute definitions. The first
Attribute may be used to carry a set of certificates or public keys that
may be necessary to validate evidence. The second Attribute carries a
structure that may be used to carry key attestation statements, signatures
and related data.

A CSR may contain one or more attestations, for example a key attestation
asserting the storage properties of the private key as well as a platform
attestation asserting the firmware version and other general properties
of the device, or multiple key attestations signed by certificate chains
on different cryptographic algorithms.

With these attributes, an RA or CA has additional
information about whether to issuer a certificate and what information
to populate into the certificate. The scope of this document is, however,
limited to the transport of evidence via a CSR. A supplementary document
will describe how evidence is carried in an X.509 certificate for attesting
hardware security modules (HSMs).

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

~~~
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

~~~
-- Root of IETF's PKIX OID tree
id-pkix OBJECT IDENTIFIER ::= { iso(1) identified-organization(3)
     dod(6) internet(1) security(5) mechanisms(5) pkix(7) }

-- S/Mime attributes - can be used here.
id-aa OBJECT IDENTIFIER ::= {iso(1) member-body(2) usa(840)
     rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) attributes(2)}

-- Branch for attestation statement types
id-ata OBJECT IDENTIFIER ::= { id-pkix (TBD1) }
~~~

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
with RFC5280.  Enforcement of this constraint is left to the relying
parties.

"opaqueCert" should be used sparingly as it requires the receiving
party to implictly know its format.  It is encoded as an OCTET
STRING.

"TypedCert" is an ASN.1 construct that has the charateristics of a
certificate, but is not encoded as an X.509 certificate.  The
certTypeField indicates how to interpret the certBody field.  While
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
encoding.  Think compact or implicit certificates as might be used
with smart cards.  certType indicates the format of the data in the
certBody field, and ideally refers to a published specification.

~~~
TypedFlatCert ::= SEQUENCE {
    certType OBJECT IDENTIFIER,
    certBody OCTET STRING
}
~~~

## AttestAttribute

By definition, Attributes within a Certification Signing Request are
typed as ATTRIBUTE.  This attribute definition contains one or more
attestation statements of a type "AttestStatement".

~~~
id-aa-attestStatement OBJECT IDENTIFIER ::= { id-aa (TBDAA2) }

AttestAttribute ATTRIBUTE ::= {
  TYPE AttestStatement
  IDENTIFIED BY id-aa-attestStatement
}
~~~

A CSR MAY contain one or more instance of `AttestAttribute` to allow,
for example a key attestation
asserting the storage properties of the private key as well as a platform
attestation asserting the firmware version and other general properties
of the device, or multiple key attestations signed by certificate chains
on different cryptographic algorithms.

##  AttestCertsAttribute

The "AttestCertsAttribute" contains a sequence of certificates that
may be needed to validate the contents of an attestation statement
contained in an attestAttribute. The set of certificates should contain
the object that contains the public key needed to directly validate the
AttestAttribute.  The remaining elements should chain that data back to
an agreed upon root of trust for attestations. No order is implied, it is
the Verifier's responsibility to perform the appropriate certificate path building.

A CSR MUST contain at most 1 `AttestCertsAttribute`. In the case where
the CSR contains multiple instances of `AttestAttribute` representing
multiple attestations, all necessary certificates MUST be contained in
the same instance of `AttestCertsAttribute`.

~~~
id-aa-attestChainCerts OBJECT IDENTIFIER ::= { id-aa (TBDAA1) }

AttestCertsAttribute ATTRIBUTE ::= {
  TYPE SET OF CertificateChoice
  COUNTS MAX 1
  IDENTIFIED BY id-aa-attestChainCerts
}
~~~


##  AttestStatement

An AttestStatement is an object of class ATTEST-STATEMENT encoded as
a sequence fields, of which the type of the "value" field is
controlled by the value of the "type" field, similar to an Attribute
definition.

~~~
AttestStatement ::= SEQUENCE
  {
    type   OBJECT IDENTIFIER,
    value  OCTET STRING
  }
~~~


# ASN.1 Module

~~~
{::include CSR-ATTESTATION-2023.asn}
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
  - Description: id-aa-attestStatement
  - References: This Document

- Attest Certificate Chain

  - Decimal: IANA Assigned - Replace TBDAA1
  - Description: id-aa-attestChainCerts
  - References: This Document

###  "SMI Security for PKIX Attestation Statement Formats" Registry

Please open up a registry for Attestation Statement Formats within
the SMI-numbers registry, allocating an assignment from id-pkix ("SMI
Security for PKIX" Registry) for the purpose.

-  Decimal: IANA Assigned - replace TBD1
-  Description: id-ata
-  References: This document
-  Initial contents: None
-  Registration Regime: Specification Required.
   Document must specify an ATTEST-STATEMENT definition to which this Object Identifier shall be bound.

Columns:

-  Decimal: The subcomponent under id-ata
-  Description: Begins with id-ata
-  References: RFC or other document

# Security Considerations

The attestation evidence communicated in the attributes and
structures defined in this document are meant to be used in
a PKCS10 Certification Signing Request (CSR). It is up to the
verifier and to the relying party (RA/CA) to place as much or
as little trust in this information as dictated by policies.

This document defines the transport of evidence of different formats
in a CSR. Some of these attestation formats are based on standards
while others are proprietary formats. A verifier will need to understand
these formats for matching the received values against policies.

Policies drive the processing of evidence at the verifier and other
policies influence the decision making at the relying party when
evaluating the attestation result. The relying party is ultimately
responsible for making a decision of what attestation-related
information in the CSR it will accept. The presence of the attributes
defined in this specification provide the relying party with additional
assurance about attester. Policies used at the verifier and the relying
party are implementation dependent and out of scope for this document.
Whether to require the use of the attestation-related attributes in the
CSR is out-of-scope for this document.

Evidence generated by the attestation needs to be fresh to provide
value to the verifier since the configuration on the device may change
over time. Section 10 of {{RFC9334}} discusses different approaches for
providing freshness, including a nonce-based approach, the use of timestamps
and an epoch-based technique.  The use of nonces requires an extra message
exchange via the relying party and the use of timestamps requires
synchronized clocks. Epochs also require communication. Constraints in
certain deployment environments may make these of these techniques
impossible. Hence, whether to require the use one of these
freshness techniques is out-of-scope for this document. Developers
and operators need to analyse the impact of replayed evidence.
The distribution of nonces via certificate management protocols, some of
which embed CSRs, is possible but out-of-scope for this document.

--- back

# Acknowledgments

This specification is the work of a design team created by the chairs of the
LAMPS working group (). The following persons, in no specific order,
contributed to the work: Richard Kettlewell, Chris Trufan, Bruno Couillard,
Jean-Pierre Fiset, Sander Temme, Jethro Beekman, Zsolt Rózsahegyi, Ferenc
Pető, Mike Agrenius Kushner, Tomas Gustavsson, Dieter Bong, Christomer Meyer,
Michael StJohns, Carl Wallace, Michael Ricardson, Tomofumi Okubo, Olivier
Couillard, John Gray, Eric Amador, Johnson Darren, Herman Slatman, Tiru Reddy,
Thomas Fossati, Corey Bonnel, Argenius Kushner, James Hagborg.

We would like to specifically thank Mike StJohns for his work on an earlier
version of this draft.

# Examples

This section provides two non-normative examples for embedding evidence
in in CSRs. The first example embeds the Arm Platform Security Architecture
tokens, which offers platform attestation, into the CSR. The second example
conveys TPM v2.0 attestation information in the CSR.

## PSA Attestation in CSR

TBD. Example based on {{I-D.tschofenig-rats-psa-token}}.

##  TPM V2.0 Attestation in CSR

TBD: Example based on {{TPM20}}.

# ASN.1 Module for Attestation

TBD.
