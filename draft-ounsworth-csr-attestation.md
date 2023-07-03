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
 - next generation
 - unicorn
 - sparkling distributed ledger
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

normative:
    RFC9334:
    RFC5912:

informative:
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

Remote attestation allows a relying party, the Registration Authority or the
Certification Authority, to learn about the security posture of a verifier,
which in the context of this specification is a device transmitting a
certification request using the newly defined attestation extension.

As outlined in RFC 9334 {{RFC9334}}, a verifier collects claims from its target
environment and gets those claims signed by the attesting environment. The
details of what claims are collected, how they are signed and what formats
for serialization are used vary with a given attestation technology. At the
time of writing several standardized and proprietary attestation technologies
are in use. This specification thereby tries to be technology agnostic with
regards to the transport of the produced signed claims.

RFC 9334 uses the term “evidence” for the information that is communicated
by the verifier with remote parties. Since the information produced by the
device can neither be trusted and often not even verified directly by the
relying party an additional role with the verifier is introduced. The verifier
has knowledge to verify the evidence, has information about what devices run
what firmware and software, etc.

This document creates two ATTRIBUTE/Attribute definitions. The first
Attribute may be used to carry a set of certificates or public keys that
may be necessary to validate evidence.  The second Attribute carries a
structure that may be used to carry key attestation statements, signatures
and related data.

With these extensions a Certification Authority (CA) has additional
information about whether to issuer a certificate and what information
to populate into the certificate.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document re-uses the terms defined in RFC 9334 related to remote
attestation. Readers of this document are assumed to be familiar with
the following terms: evidence, claim, attestation result, attester,
verifier, and relying party.

# Architecture

{{fig-arch}} shows the high-level communication pattern of the passport 
model where the attester transmits the evidence in the CSR to the RA
and the CA. The verifier processes the received evidence and computes
an attestation result, which is the processed by the RA/CA prior to the
certificate issuance. Note that the verifier is a logical role that may
be included in the RA/CA product. In this case the interaction between
the relying party and the verifier are local.

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
 |            +-------------->|---'           | Compare Attestation
 |  Attester  |   Evidence    | Relying       | Result against
 |            |   in CSR      | Party (RA/CA) | policy
 '------------'               '---------------'
~~~
{: #fig-arch title="Architecture"}

As discussed in RFC 9334 different security and privacy aspects need to be
considered. For example, evidence may need to be protected against replay and
Section 10 of RFC 9334 lists approach for offering freshness. There are also
concerns about the exposure of persistent identifiers by utilizing attestation
technology, which are discussed in Section 11 of RFC 9334. Finally, the keying
material used by the attester need to be protected against unauthorized access.
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
      cert Certificate, -- typical X.509 cert
      opaqueCert    [0] IMPLICIT OCTET STRING, -- Format implicitly agreed upon
                                               -- by sender and receiver
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
TYPED-CERT ::= TYPE-IDENTIFIER -- basically an object id and a matching ASN1
                               -- structure encoded as a sequence
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

##  AttestCertsAttribute

   The "AttestCertsAttribute" contains a sequence of certificates that
   may be needed to validate the contents of an attestation statement
   contained in an attestAttribute.  By convention, the first element of
   the SEQUENCE SHOULD contain the object that contains the public key
   needed to directly validate the attestAttribute.  The remaining
   elements should chain that data back to an agreed upon root of trust
   for the attestation.

~~~
id-aa-attestChainCerts OBJECT IDENTIFIER ::= { id-aa (TBDAA1) }

attestCertsAttribute ATTRIBUTE ::= {
  TYPE SEQUENCE OF CertificateChoice
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
ATTEST-STATEMENT ::= CLASS {
  &id                 OBJECT IDENTIFIER UNIQUE,
  &Type,                  -- NOT optional
  &algidPresent       ParamOptions DEFAULT absent,
  &sigPresent         ParamOptions DEFAULT absent,
  &ancillaryPresent   ParamOptions DEFAULT absent,
  &sigType            DEFAULT OCTET STRING
  &ancillaryType      DEFAULT OCTET STRING

} WITH SYNTAX {
  TYPE  &Type
  IDENTIFIED BY &id
  [ALGID IS &algidPresent]
  [SIGNATURE [TYPE &sigType] IS &sigPresent]
  [ANCILLARY [TYPE &ancillaryType] IS &ancillaryPresent]
}

AttestStatement { ATTEST-STATEMENT:IOSet}  ::= SEQUENCE
  {
    type          ATTEST-STATEMENT.&id({IOSet}),
    value         ATTEST-STATEMENT.&Type({IOSet}{@type}),
    algId         [0] IMPLICIT  AlgorithmIdentifier OPTIONAL,
    signature     [1] ATTEST-STATEMENT.&sigType OPTIONAL -- NOT implicit
    ancillaryData [2] ATTEST-STATEMENT.&ancillaryType OPTIONAL
  }
~~~

   Depending on whether the "value" field contains an entire signed
   attestation, or only the toBeSigned portion, the algId field may or
   may not be present.  If present it contains the AlgorithmIdentifier
   of the signature algorithm used to sign the attestation statement.
   If absent, either the value field contains an indication of the
   signature algorithm, or the signature algorithm is fixed for that
   specific type of AttestStatement.

   Similarly for the "signature" field, if the "value" field contains
   only the toBeSigned portion of the attestation statement, this field
   SHOULD be present.  The "signature" field may by typed as any valid
   ASN.1 type.  Opaque signature types SHOULD specify the use of sub-
   typed OCTET STRING.  For example:

~~~
MyOpaqueSignature ::= OCTET STRING
~~~

   If possible, the ATTEST-STATEMENT SHOULD specify an un-wrapped
   representation of a signature, rather than an OCTET STRING or BIT
   STRING wrapped ASN.1 structure.  I.e., by specifying ECDSA-Sig-Value
   from PKIXAlgs-2009 (see {{RFC5912}}) to encode an ECDSA signature.

~~~
ECDSA-Sig-Value ::= SEQUENCE {
  r  INTEGER,
  s  INTEGER
}
~~~

   The ancillaryData field contains data provided externally to the
   attestation engine,and/or data that may be needed to relate the
   attestation to other PKIX elements.  The format or content of the
   externally provided data is not under the control of the attestation
   engine.  For example, this field might contain a freshness nonce
   generated by the relying party, a signed time stamp, or even a hash
   of protocol data or nonce data.  See below for a few different
   examples.

# IANA Considerations

The IANA is requested to open one new registrie, allocate a value
from the "SMI Security for PKIX Module Identifier" registry for the
included ASN.1 module, and allocate values from "SMI Security for S/
MIME Attributes" to identify two Attributes defined within.

##  Object Identifier Allocations

###  Module Registration - SMI Security for PKIX Module Identifer

-  Decimal: IANA Assigned - Replace TBDMOD
-  Description: Attest-2023 - id-mod-pkix-attest-01
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

The attributes and structures defined in this document are primarily
meant to be used as additional Attributes for a PKCS10 Certification
Signing Request (CSR).  As such, it's up to the receiving/relying
party to place as much or as little trust in the contents of these
attributes as necessary to satisfy its own policies.

A relying party will need either a specification defining how an
attestation type was formed and how to validate that type, or a
trusted method of verifying the attestation.  In the former case, a
relying party should consider the information available from any
certificate chain covering the attesting key when deciding to accept
the attestation.

Most attestations will need to provide a method to convert the
attested key representation into the equivalent SubjectPublicKey info
structure and the attested key MUST be compared for equivalence to
the public key provided in the CSR before accepting the attestation.

The relying party, as always, is responsible for setting the rules
for what it will accept.  The presence of an AttestAttribute is not
required by any current standard, but such attribute may provide the
relying party with additional assurance as a prerequisite to issuing
certificates or other credentials.  That acceptance criteria is out
of scope for this document.  Whether to require an AttestAttribute or
its contents in any specific use case is out-of-scope for this
document.

--- back

# Acknowledgments

Add your name here.

# Examples

## Simple Attestation Example

   This is a fragment of ASN.1 meant to demonstrate an absolute minimal
   definition of an ATTEST-STATEMENT.  A similar fragment could be used
   to define an ATTEST-STATEMENT for an opaque HSM vendor specific
   atterstation model.

~~~
-- This OCTET STRING is not like any other OCTET STRING
-- Please see https://example.com/simple-attest.txt,
-- Structure labled "Mike's simple attest" for the
-- structure of this field and how to verify the attestation

MikesSimpleAttestData ::= OCTET STRING

mikesSimpleAttestOid OBJECT IDENTIFIER ::= { id-mikes-root 1 }

MikesSimpleAttest ATTEST-STATEMENT ::= {
  TYPE MikesSimpleAttestData
  IDENTIFIED BY mikesSimpleAttestOid
  -- These are all implied
  -- ALGID IS absent
  -- SIGNATURE is absent
  -- ANCILLARY is absent
}
~~~

##  Example TPM V2.0 Attestation Attribute - Non Normative

   What follows is a fragment of an ASN.1 module that might be used to
   define an attestation statment attribute to carry a TPM V2.0 key
   attestation - i.e., the output of the TPM2_Certify command.  This is
   an example and NOT a registered definition.  It's provided simply to
   give an example of how to write an ATTEST-STATEMENT definition and
   module.

~~~
-- IMPORT these.
-- PKI normal form for an ECDSA signature
ECDSA-Sig-Value ::= SEQUENCE {
  r INTEGER,
  s INTEGER
  }

-- Octet string of size n/8 where n is the
-- bit size of the public modulus
RSASignature ::= OCTET STRING

-- One or the other of these depending on the value in TPMT_SIGNATURE

TpmSignature CHOICE ::= {
  ecSig [0] IMPLICIT ECDSA-Sig-Value,
  rsaSig [1] IMPLICIT RSASignature
  }

-- The TPM form of the public key being attested.
-- Needed to verify the attestation - this is the TPMT_PUBLIC structure.
TpmtPublic ::= OCTET STRING

-- The TPMS_ATTEST structure as defined in TPM2.0
-- Unwrapped from the TPM2B_ATTEST provided
-- by the TPM2_Certify command.
TpmsAttest ::= OCTET STRING

-- The qualifying data provided to a TPM2_Certify call, may be absent
-- This is the contents of data field of the TPM2B_DATA structure.
QualifyingData ::= OCTET STRING

TpmAncillary ::= SEQUENCE {
   toBeAttestedPublic TpmtPublic,
   qualifyingData QualifyingData OPTIONAL
   }

-- This represents a maximally unwrapped TPM V2.0 attestation.  The
-- output of TPM2_Certify is a TPM2B_ATTEST and a TPMT_SIGNATURE.
-- The former is unwrapped into a TPMS_ATTEST and the latter is
-- decomposed to provide the contents of the algId and signature fields.

--
-- This attestation statement can be verified by:
-- Signature siggy = Signature.getInstance (stmt.algId);
-- siggy.init (attestPublicKey, VERIFY);
-- siggy.update ((short)stmt.value.length) // todo: big or little endian
-- siggy.update (stmt.value.data)
-- bool verified = siggy.verify (getSigData(stmt.signature)); //
unwrap the signature
--

TpmV2AttestStatement ATTEST STATEMENT ::= {
   TYPE TpmsAttest
   IDENTIFIED BY id-ata-tpmv20-1
   ALGID IS present
   SIGNATURE TYPE TpmSignature IS present
   ANCILLARY TYPE TpmAncillary IS present
   }
~~~

   This attestation is the result of executing a TPM2_Certify command
   over a TPM key.  See {{TPM20}} for more details.

   The data portion of the value field encoded as OCTET STRING is the
   attestationData from the TPM2B_ATTEST produced by the TPM.  In other
   words, strip off the TPM2B_ATTEST "size" field and place the
   TPMS_ATTEST encoded structure in the OCTET STRING data field.

   The algId is derived from the "sigAlg" field of the TPMT_SIGNATURE
   structure.

   The signature field is a TpmSignature, created by transforming the
   TPMU_SIGNATURE field to the appropriate structure given the signature
   type.

   The ancillary field contains a structure with the TPMT_PUBLIC
   structure that contains the TPM's format of the key to be attested.
   The attestation statement data contains a hash of this structure, and
   not the key itself, so the hash of this structure needs to be
   compared to the value in the attestation attestation statement.  If
   that passes, the key needs to be transformed into a PKIX style key
   and compared to the key in the certificate signing request to
   complete the attestation verification.

   The ancillary field also contains an optional OCTET STRING which is
   used if the TPM2_Certify command is called with a non-zero length
   "qualifyingData" argument to contain that data.

   An AttestCertChain attribute MUST be present if this attribute is
   used as part of a certificate signing request.

# ASN.1 Module for Attestation

TBD.
