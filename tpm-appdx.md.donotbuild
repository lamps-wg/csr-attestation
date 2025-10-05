informative:
  TPM20:
    author:
      org: Trusted Computing Group
    title: Trusted Platform Module Library Specification, Family 2.0
    target: https://trustedcomputinggroup.org/resource/tpm-library-specification/


##  TPM V2.0 Evidence in CSR {#appdx-tpm2}

This section describes TPM2 key attestation for use in a CSR.

This is a complete and canonical example that can be used to test parsers implemented against this specification. Readers who wish the sample data may skip to {{appdx-tpm-example}}; the following sections explain the TPM-specific data structures needed to fully parse the contents of the evidence statement.

### TCG Key Attestation Certify

There are several ways in TPM2 to provide proof of a key's properties.
(i.e., key attestation). This description uses the simplest and most generally
expected to be used, which is the TPM2_Certify and the TPM2_ReadPublic commands.

This example does not describe how platform attestation augments key attestation.
The properties of the key (such as the name of the key, the key usage) in this example
do not change during the lifetime of the key.

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

The definitions in the following sections are specified by the Trusted Computing Group (TCG). TCG specification including the TPM2 set of specifications {{TPM20}}, specifically Part 2 defines the TPM 2.0 structures.
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
      EvidenceBundle {
        Evidences {
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
~~~

Note that this example demonstrates most of the features of this specification:

- The data type is identified by the OID id-TcgCsrCertify contained in the `EvidenceStatement.type` field.
- The signed evidence is carried in the `EvidenceStatement.stmt` field.
- The `EvidenceStatement.hint` provides information to the Relying Party about which Verifier (software) will be able to correctly parse this data. Note that the `type` OID indicates the format of the data, but that may itself be a wrapper format that contains further data in a proprietary format. In this example, the hint says that software from the package `"tpmverifier.example.com"` will be able to parse this data.
- The evidence statement is accompanied by a certificate chain in the `EvidenceBundle.certs` field which can be used to verify the signature on the evidence statement. How the Verifier establishes trust in the provided certificates is outside the scope of this specification.

This example does not demonstrate an EvidenceBundle that contains multiple EvidenceStatements sharing a certificate chain.

~~~
{::include-fold sampledata/tcgAttestTpmCertify.pem}
~~~
