# Samelex

SAML library for Elixir by Kbrw.

**CURRENTLY NOT ENOUGH GENERIC FOR EXTERNAL USE, public API May change**
API will be freeze shortly.

## Features

Current Features : 

- SAML Single Logout management
- SAML Assertion parsing
- SAML Assertion and Envelop Signature check
- AuthN Request signature management
- Handle HTTP Redirect and HTTP Post binding
- SP Metadata management

Current attribute OID managed : 

- employee_number: "urn:oid:2.16.840.1.113730.3.1.3",
- eduPersonPrincipalName: "urn:oid:1.3.6.1.4.1.5923.1.1.1.6",
- mail: "urn:oid:0.9.2342.19200300.100.1.3",
- givenName: "urn:oid:2.5.4.42",
- displayName: "urn:oid:2.16.840.1.113730.3.1.241",
- commonName: "urn:oid:2.5.4.3",
- telephoneNumber: "urn:oid:2.5.4.20",
- organizationName: "urn:oid:2.5.4.10",
- organizationalUnitName: "urn:oid:2.5.4.11",
- eduPersonScopedAffiliation: "urn:oid:1.3.6.1.4.1.5923.1.1.1.9",
- employeeType: "urn:oid:2.16.840.1.113730.3.1.4",
- uid: "urn:oid:0.9.2342.19200300.100.1.1",
- surName: "urn:oid:2.5.4.4"

## Will be open-sourced shortly 

- Use a database to import attributes OID
- Idp Metadata management
- Idp Assertion signature
- Idp AuthN signature check
- SOAP Bindings
- AUthn, Assertion and Attribute encryption
