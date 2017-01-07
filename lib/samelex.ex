defmodule Samelex do
  import SweetXml, except: [sigil_x: 2,parse: 1]
  import Samelex.C14n, only: [strip: 1, c14n: 3, c14n: 1]

  def sigil_x(str,opts) do
    SweetXml.sigil_x(str,opts)
    |> add_namespace("samlp","urn:oasis:names:tc:SAML:2.0:protocol")
    |> add_namespace("saml","urn:oasis:names:tc:SAML:2.0:assertion")
    |> add_namespace("md","urn:oasis:names:tc:SAML:2.0:metadata")
    |> add_namespace("ds","http://www.w3.org/2000/09/xmldsig#")
  end
  def parse(xml) do
    SweetXml.parse(xml,namespace_conformant: true)
  end

  #def xmap(el,specs) when is_tuple(el), do: SweetXml.xmap(el,specs)
  #def xmap(xml,specs), do: xml |> parse(namespace_conformant: true) |> SweetXml.xmap(specs)
  #def xpath(el,spec,specs) when is_tuple(el), do: SweetXml.xpath(el,spec,specs)
  #def xpath(xml,spec,specs), do: xml |> parse(namespace_conformant: true) |> SweetXml.xpath(spec,specs)

  @status [
    success:      "urn:oasis:names:tc:SAML:2.0:status:Success",
    bad_version:  "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch",
    authn_failed: "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
    bad_attr:     "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue",
    denied:       "urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
    bad_binding:  "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding"
  ]
  @name [
    email:        "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    x509:         "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName",
    windows:      "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName",
    krb:          "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos",
    persistent:   "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
    transient:    "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
  ]
  @method [
    bearer:       "urn:oasis:names:tc:SAML:2.0:cm:bearer"
  ]
  @logout_reason [
    user:         "urn:oasis:names:tc:SAML:2.0:logout:user",
    admin:        "urn:oasis:names:tc:SAML:2.0:logout:admin"
  ]
  @attrib [
    employee_number: "urn:oid:2.16.840.1.113730.3.1.3",
    eduPersonPrincipalName: "urn:oid:1.3.6.1.4.1.5923.1.1.1.6",
    mail: "urn:oid:0.9.2342.19200300.100.1.3",
    givenName: "urn:oid:2.5.4.42",
    displayName: "urn:oid:2.16.840.1.113730.3.1.241",
    commonName: "urn:oid:2.5.4.3",
    telephoneNumber: "urn:oid:2.5.4.20",
    organizationName: "urn:oid:2.5.4.10",
    organizationalUnitName: "urn:oid:2.5.4.11",
    eduPersonScopedAffiliation: "urn:oid:1.3.6.1.4.1.5923.1.1.1.9",
    employeeType: "urn:oid:2.16.840.1.113730.3.1.4",
    uid: "urn:oid:0.9.2342.19200300.100.1.1",
    surName: "urn:oid:2.5.4.4"]
  for attr<-[:method,:logout_reason,:name,:status,:attrib], {atom,ns}<-Module.get_attribute(__MODULE__,attr), do:
    def ns_for(unquote(attr),unquote(atom)), do: unquote(ns)
  for attr<-[:method,:logout_reason,:name,:status,:attrib], {atom,ns}<-Module.get_attribute(__MODULE__,attr), do:
    def atomize(unquote(attr),unquote(ns)), do: unquote(atom)
  def atomize(:attrib,val), do: String.to_atom(val)
  def atomize(_,_), do: :unknown

  def idp_metadata(xml) do
    xml |> parse() |> xmap(
      entity: ~x"/md:EntityDescriptor/@entityID"s,
      login_url: ~x"/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']/@Location"s,
      logout_url: ~x"/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleLogoutService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']/@Location"s,
      name_format: ~x"/md:EntityDescriptor/md:IDPSSODescriptor/md:NameIDFormat/text()"s |> transform_by(&atomize(:name,&1)),
      cert: ~x"/md:EntityDescriptor/md:IDPSSODescriptor/md:KeyDescriptor[@use='signing']/ds:KeyInfo/ds:X509Data/ds:X509Certificate/text()"s |> transform_by(&soft_decode_64!/1),
      tech: [~x"/md:EntityDescriptor/md:ContactPerson[@contactType='technical']"e,
        email: ~x"/md:ContactPerson/md:EmailAddress/text()"s,
        first_name: ~x"/md:ContactPerson/md:GivenName/text()"s,
        last_name: ~x"/md:ContactPerson/md:SurName/text()"s],
      org: [~x"/md:EntityDescriptor/md:Organization"e,
        name: ~x"/md:Organization/md:OrganizationName/text()"s,
        display_name: ~x"/md:Organization/md:OrganizationDisplayName/text()"s,
        url: ~x"/md:Organization/md:OrganizationURL/text()"s])
  end

  def logout_request(xml) do
    xml |> parse() |>  xmap(
      version: ~x"/samlp:LogoutRequest/@Version"s,
      instant: ~x"/samlp:LogoutRequest/@IssueInstant"s,
      name: ~x"/samlp:LogoutRequest/saml:NameID/text()"s,
      dest: ~x"/samlp:LogoutRequest/@Destination"s,
      reason: ~x"/samlp:LogoutRequest/@Reason"s |> transform_by(&atomize(:logout_reason,&1)),
      issuer: ~x"/samlp:LogoutRequest/saml:Issuer/text()"s)
  end

  def logout_response(xml) do
    xml |> parse() |> xmap(
      version: ~x"/samlp:LogoutResponse/@Version"s,
      instant: ~x"/samlp:LogoutResponse/@IssueInstant"s,
      status: ~x"/samlp:LogoutResponse/samlp:Status/samlp:StatusCode/@Value"s |> transform_by(&atomize(:status,&1)),
      dest: ~x"/samlp:LogoutResponse/@Destination"s,
      issuer: ~x"/samlp:LogoutResponse/saml:Issuer/text()"s)
  end

  def login_response(xml) do
    xml |> parse() |> xmap(
      version: ~x"/samlp:Response/@Version"s,
      instant: ~x"/samlp:Response/@IssueInstant"s,
      dest: ~x"/samlp:Response/@Destination"s,
      issuer: ~x"/samlp:Response/saml:Issuer/text()"s,
      status: ~x"/samlp:Response/samlp:Status/samlp:StatusCode/@Value"s |> transform_by(&atomize(:status,&1)),
      assertion: [~x"/samlp:Response/saml:Assertion"e,
        version: ~x"/saml:Assertion/@Version"s,
        instant: ~x"/saml:Assertion/@IssueInstant"s,
        recipient: ~x"/saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@Recipient"s,
        issuer: ~x"/saml:Assertion/saml:Issuer/text()"s,
        subject: [ ~x"/saml:Assertion/saml:Subject"e,
          name: ~x"/saml:Subject/saml:NameID/text()"s,
          method: ~x"/saml:Subject/saml:SubjectConfirmation/@Method"s |> transform_by(&atomize(:method,&1)),
          notonorafter: ~x"/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@NotOnOrAfter"s,
        ],
        conditions: [~x"/saml:Assertion/saml:Conditions"l,
          not_before: ~x"./@NotBefore"s,
          not_on_or_after: ~x"./@NotOnOrAfter"s,
          audience: ~x"/saml:Conditions/saml:AudienceRestriction/saml:Audience/text()"s
        ],
        attributes: ~x"/saml:Assertion/saml:AttributeStatement"e |> transform_by(fn 
          nil-> %{}
          attrs-> 
            xpath(attrs,~x"/saml:AttributeStatement/saml:Attribute"l,
              k: ~x"./@Name"s |> transform_by(&atomize(:attrib,&1)),
              v: ~x"saml:AttributeValue/text()"s
            ) |> Enum.into(%{},&{&1.k,&1.v})
        end)
     ])
  end

  def verify_sigs(xml,acceptcert) do
    e = if is_tuple(xml), do: xml, else: parse(xml)
    envelop_sign = xpath(e,~x"ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm"e) != nil
    assertion_sign = xpath(e,~x"saml:Assertion/ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm"e) != nil
    case {envelop_sign,assertion_sign} do
      {false,false}->{:error,:no_signature}
      {true,false}->verify_sig(e,acceptcert)
      {_,true}->verify_sig(xpath(e,~x"saml:Assertion"e),acceptcert)
    end
  end

  def soft_decode_64!(str) do
    str |> String.replace(~r/[\n\r\s]/,"") |> Base.decode64!()
  end

  def verify_sig(xml,acceptcert) do
    e = if is_tuple(xml), do: xml, else: parse(xml)
    algo = xpath(e,~x"ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm"s)
    hash_algo = case algo do
      "http://www.w3.org/2000/09/xmldsig#rsa-sha1"-> :sha
      "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"-> :sha256
    end
    "http://www.w3.org/2001/10/xml-exc-c14n#" = xpath(e,~x"ds:Signature/ds:SignedInfo/ds:CanonicalizationMethod/@Algorithm"s)
    c14ntx = xpath(e,~x"ds:Signature/ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform[@Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#']"e)
    incl_ns = case xpath(c14ntx,~x"ec:InclusiveNamespaces/@PrefixList"s) do ""-> []; other-> String.split(other," ,") end |> Enum.map(&to_char_list/1)
    canon = e |> strip() |> c14n(false,incl_ns) |> :unicode.characters_to_binary(:unicode,:utf8)
    hash = :crypto.hash(hash_algo,canon)
    hash64 = xpath(e,~x"ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue/text()"s)
    if soft_decode_64!(hash64) != hash do
      {:error,:bad_digest}
    else
      data = e |> xpath(~x"ds:Signature/ds:SignedInfo"e) |> c14n() |> :unicode.characters_to_binary(:unicode,:utf8)
      sig = e |> xpath(~x"ds:Signature//ds:SignatureValue/text()"s) |> soft_decode_64!()
      certbin = e |> xpath(~x"ds:Signature//ds:X509Certificate/text()"s) |> soft_decode_64!()
      {:Certificate,{:TBSCertificate,_,_,_,_,_,_,{:SubjectPublicKeyInfo,_,keybin},_,_,_},_,_} = :public_key.pkix_decode_cert(certbin,:plain)
      key = :public_key.pem_entry_decode({:RSAPublicKey,keybin,:not_encrypted})
      if soft_decode_64!(acceptcert) == certbin do
        if :public_key.verify(data,hash_algo,sig,key) do
          {:ok,[Base.encode16(:crypto.hash(:sha,certbin)),Base.encode16(:crypto.hash(:sha256,certbin))]}
        else
          {:error,:bad_sig}
        end
      else
        {:error,:cert_nomatch}
      end
    end
  end

  #def stale_time(_assertion) do
  #  _assertion = %{attributes: %{eduPersonAffiliation: "usersexamplerole1",
  #    mail: "test@example.com", uid: "test"},
  #  conditions: [%{audience: "http://sp.example.com/demo1/metadata.php",
  #     not_before: "2014-07-17T01:01:18Z",
  #     not_on_or_after: "2024-01-18T06:21:48Z"}],
  #  instant: "2014-07-17T01:01:48Z",
  #  issuer: "http://idp.example.com/metadata.php",
  #  recipient: "http://sp.example.com/demo1/index.php?acs",
  #  subject: %{method: :bearer,
  #    name: "_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7",
  #    notonorafter: "2024-01-18T06:21:48Z"}, version: "2.0"}
  #  #assertion.subject[:not_on_or_after] && Timex.parse(
  #  # take lowest value of "subject.notonorafter", "conditions.notonorafter",
  #  # if no value for these to fields, take issue_instant + 5min
  #end

  #def check_stale(_assertion) do
  #  ## ok if now < stale_time (assertion)
  #  true
  #end

  def authnreq(sp_entity,idp_dest), do: authnreq(sp_entity,idp_dest,nil)
  def authnreq(sp_entity,idp_dest, nil) do
    """
    <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                        AssertionConsumerServiceIndex="0"
                        IssueInstant="#{Timex.format!(%{DateTime.utc_now|microsecond: {0,0}},"{ISO:Extended:Z}")}"
                        Destination="#{idp_dest}"
                        Version="2.0"
                        ID="#{"a"<>Base.encode16(:crypto.strong_rand_bytes(10))}">
       <saml:Issuer>#{sp_entity}</saml:Issuer>
       <saml:Subject><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"/></saml:Subject>
    </samlp:AuthnRequest>
    """
  end
  def authnreq(sp_entity,idp_dest, sp_post_url) do
    """
    <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                        xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                        AssertionConsumerServiceURL="#{sp_post_url}"
                        ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                        IssueInstant="#{Timex.format!(%{DateTime.utc_now|microsecond: {0,0}},"{ISO:Extended:Z}")}"
                        Destination="#{idp_dest}"
                        Version="2.0"
                        ID="#{"a"<>Base.encode16(:crypto.strong_rand_bytes(10))}">
       <saml:Issuer>#{sp_entity}</saml:Issuer>
       <saml:Subject><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"/></saml:Subject>
    </samlp:AuthnRequest>
    """
  end
  def authnreq_signed(sp_entity,idp_dest,cert,key,sp_post_url \\ nil) do
     sign_authn(authnreq(sp_entity,idp_dest,sp_post_url),cert,key)
  end

  def sign_authn(xml,cert64,keypem) do
    newid = "a"<>Base.encode16(:crypto.strong_rand_bytes(10))
    xml = String.replace(xml,~r/ID="[^"]*"/,~s/ID="#{newid}"/)
    canon = parse(xml) |> strip() |> c14n(false,[]) |> :unicode.characters_to_binary(:unicode,:utf8)
    tosign = """
    <ds:SignedInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="##{newid}">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
        <ds:DigestValue>#{:crypto.hash(:sha,canon) |> Base.encode64}</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    """
    priv_key = keypem |> :public_key.pem_decode() |> hd |> :public_key.pem_entry_decode()
    sig = parse(tosign) |> c14n() |> :unicode.characters_to_binary(:unicode,:utf8) |> :public_key.sign(:sha256,priv_key) |> Base.encode64
    String.replace(xml,"</saml:Issuer>","""
      </saml:Issuer><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        #{tosign}
        <ds:SignatureValue>#{sig}</ds:SignatureValue>
        <ds:KeyInfo><ds:X509Data><ds:X509Certificate>#{cert64}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
      </ds:Signature>
      """ |> String.trim_trailing())
  end

  def http_redirect(idp_target,xml,relay_state) do
    q=URI.encode_query(%{"SAMLEncoding"=>"urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE",
                        "SAMLRequest"=> (xml |> :zlib.zip |> Base.encode64),
                        "RelayState"=> relay_state})
    idp_target <> if(String.contains?(idp_target,"?"), do: "&", else: "?") <> q
  end

  def parse_post(form_body) do
    q = URI.decode_query(form_body)
    %{response: q["SAMLResponse"] |> soft_decode_64!(),
      relay_state: q["RelayState"]}
  end
end
