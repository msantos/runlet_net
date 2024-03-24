-module(runlet_x509).

-include_lib("public_key/include/public_key.hrl").

-export([
    info/1,

    public_key/1,
    version/1,
    serial_number/1,
    signature_algorithm/1,
    issuer/1,
    not_before/1,
    not_after/1,
    subject/1,
    get_value/1
]).

info(X509) ->
    #{
        data => #{
            version => version(X509),
            serialNumber => serial_number(X509)
        },

        signatureAlgorithm => signature_algorithm(X509),

        issuer => issuer(X509),

        validity => #{
            notBefore => not_before(X509),
            notAfter => not_after(X509)
        },
        subject => subject(X509)
    }.

public_key(X509) ->
    X509#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.subjectPublicKeyInfo#'OTPSubjectPublicKeyInfo'.subjectPublicKey.

version(X509) ->
    X509#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.version.

serial_number(X509) ->
    X509#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.serialNumber.

signature_algorithm(X509) ->
    sigalg(
        X509#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.signature#'SignatureAlgorithm'.algorithm
    ).

issuer(X509) ->
    to_string(rdn_sequence(X509#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.issuer)).

not_before(X509) ->
    utctime(X509#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.validity#'Validity'.notBefore).

not_after(X509) ->
    utctime(X509#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.validity#'Validity'.notAfter).

subject(X509) ->
    to_string(rdn_sequence(X509#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.subject)).

rdn_sequence({rdnSequence, Subject}) ->
    [
        {
            value(Attribute#'AttributeTypeAndValue'.type),
            case Attribute#'AttributeTypeAndValue'.value of
                {_, Str} -> Str;
                Str -> Str
            end
        }
     || [Attribute] <- Subject
    ].

get_value(OTPCert) ->
    {rdnSequence, Subject} = OTPCert#'OTPCertificate'.tbsCertificate#'OTPTBSCertificate'.subject,
    [
        {
            value(Attribute#'AttributeTypeAndValue'.type),
            case Attribute#'AttributeTypeAndValue'.value of
                {_, Str} -> Str;
                Str -> Str
            end
        }
     || [Attribute] <- Subject
    ].

to_string(N) ->
    lists:concat(lists:concat([[X, $:, $\s, maybe_string(Y), $\n] || {X, Y} <- N])).

maybe_string(N) when is_binary(N) -> binary_to_list(N);
maybe_string(N) -> N.

utctime({utcTime, UTC}) ->
    utctime(list_to_binary(UTC));
utctime(<<YY:2/bytes, MM:2/bytes, DD:2/bytes, HH:2/bytes, NN:2/bytes, SS:2/bytes, "Z">>) ->
    binary_to_list(list_to_binary(["20", YY, "-", MM, "-", DD, "T", HH, ":", NN, ":", SS, "Z"])).

value(?'dhKeyAgreement') -> "dhKeyAgreement";
value(?'pkcs-3') -> "pkcs-3";
value(?'id-sha512') -> "id-sha512";
value(?'id-sha384') -> "id-sha384";
value(?'id-sha256') -> "id-sha256";
value(?'id-sha224') -> "id-sha224";
value(?'id-mgf1') -> "id-mgf1";
value(?'id-hmacWithSHA512') -> "id-hmacWithSHA512";
value(?'id-hmacWithSHA384') -> "id-hmacWithSHA384";
value(?'id-hmacWithSHA256') -> "id-hmacWithSHA256";
value(?'id-hmacWithSHA224') -> "id-hmacWithSHA224";
value(?'id-md5') -> "id-md5";
value(?'id-md2') -> "id-md2";
value(?'id-sha1') -> "id-sha1";
value(?'sha-1WithRSAEncryption') -> "sha-1WithRSAEncryption";
value(?'sha224WithRSAEncryption') -> "sha224WithRSAEncryption";
value(?'sha512WithRSAEncryption') -> "sha512WithRSAEncryption";
value(?'sha384WithRSAEncryption') -> "sha384WithRSAEncryption";
value(?'sha256WithRSAEncryption') -> "sha256WithRSAEncryption";
value(?'sha1WithRSAEncryption') -> "sha1WithRSAEncryption";
value(?'md5WithRSAEncryption') -> "md5WithRSAEncryption";
value(?'md2WithRSAEncryption') -> "md2WithRSAEncryption";
value(?'id-RSASSA-PSS') -> "id-RSASSA-PSS";
value(?'id-pSpecified') -> "id-pSpecified";
value(?'id-RSAES-OAEP') -> "id-RSAES-OAEP";
value(?'rsaEncryption') -> "rsaEncryption";
value(?'pkcs-1') -> "pkcs-1";
value(?'sect571r1') -> "sect571r1";
value(?'sect571k1') -> "sect571k1";
value(?'sect409r1') -> "sect409r1";
value(?'sect409k1') -> "sect409k1";
value(?'secp521r1') -> "secp521r1";
value(?'secp384r1') -> "secp384r1";
value(?'secp224r1') -> "secp224r1";
value(?'secp224k1') -> "secp224k1";
value(?'secp192k1') -> "secp192k1";
value(?'secp160r2') -> "secp160r2";
value(?'secp128r2') -> "secp128r2";
value(?'secp128r1') -> "secp128r1";
value(?'sect233r1') -> "sect233r1";
value(?'sect233k1') -> "sect233k1";
value(?'sect193r2') -> "sect193r2";
value(?'sect193r1') -> "sect193r1";
value(?'sect131r2') -> "sect131r2";
value(?'sect131r1') -> "sect131r1";
value(?'sect283r1') -> "sect283r1";
value(?'sect283k1') -> "sect283k1";
value(?'sect163r2') -> "sect163r2";
value(?'secp256k1') -> "secp256k1";
value(?'secp160k1') -> "secp160k1";
value(?'secp160r1') -> "secp160r1";
value(?'secp112r2') -> "secp112r2";
value(?'secp112r1') -> "secp112r1";
value(?'sect113r2') -> "sect113r2";
value(?'sect113r1') -> "sect113r1";
value(?'sect239k1') -> "sect239k1";
value(?'sect163r1') -> "sect163r1";
value(?'sect163k1') -> "sect163k1";
value(?'secp256r1') -> "secp256r1";
value(?'secp192r1') -> "secp192r1";
value(?'ellipticCurve') -> "ellipticCurve";
value(?'certicom-arc') -> "certicom-arc";
value(?'id-ecPublicKey') -> "id-ecPublicKey";
value(?'id-publicKeyType') -> "id-publicKeyType";
value(?'ppBasis') -> "ppBasis";
value(?'tpBasis') -> "tpBasis";
value(?'gnBasis') -> "gnBasis";
value(?'id-characteristic-two-basis') -> "id-characteristic-two-basis";
value(?'characteristic-two-field') -> "characteristic-two-field";
value(?'prime-field') -> "prime-field";
value(?'id-fieldType') -> "id-fieldType";
value(?'ecdsa-with-SHA512') -> "ecdsa-with-SHA512";
value(?'ecdsa-with-SHA384') -> "ecdsa-with-SHA384";
value(?'ecdsa-with-SHA256') -> "ecdsa-with-SHA256";
value(?'ecdsa-with-SHA224') -> "ecdsa-with-SHA224";
value(?'ecdsa-with-SHA2') -> "ecdsa-with-SHA2";
value(?'ecdsa-with-SHA1') -> "ecdsa-with-SHA1";
value(?'id-ecSigType') -> "id-ecSigType";
value(?'ansi-X9-62') -> "ansi-X9-62";
value(?'id-keyExchangeAlgorithm') -> "id-keyExchangeAlgorithm";
value(?'dhpublicnumber') -> "dhpublicnumber";
value(?'id-dsaWithSHA1') -> "id-dsaWithSHA1";
value(?'id-dsa-with-sha1') -> "id-dsa-with-sha1";
value(?'id-dsa') -> "id-dsa";
value(?'id-at-clearance') -> "id-at-clearance";
value(?'id-at-role') -> "id-at-role";
value(?'id-aca-encAttrs') -> "id-aca-encAttrs";
value(?'id-aca-group') -> "id-aca-group";
value(?'id-aca-chargingIdentity') -> "id-aca-chargingIdentity";
value(?'id-aca-accessIdentity') -> "id-aca-accessIdentity";
value(?'id-aca-authenticationInfo') -> "id-aca-authenticationInfo";
value(?'id-aca') -> "id-aca";
value(?'id-ce-targetInformation') -> "id-ce-targetInformation";
value(?'id-pe-ac-proxying') -> "id-pe-ac-proxying";
value(?'id-pe-aaControls') -> "id-pe-aaControls";
value(?'id-pe-ac-auditIdentity') -> "id-pe-ac-auditIdentity";
value(?'id-ce-invalidityDate') -> "id-ce-invalidityDate";
value(?'id-holdinstruction-reject') -> "id-holdinstruction-reject";
value(?'id-holdinstruction-callissuer') -> "id-holdinstruction-callissuer";
value(?'id-holdinstruction-none') -> "id-holdinstruction-none";
value(?'holdInstruction') -> "holdInstruction";
value(?'id-ce-holdInstructionCode') -> "id-ce-holdInstructionCode";
value(?'id-ce-certificateIssuer') -> "id-ce-certificateIssuer";
value(?'id-ce-cRLReasons') -> "id-ce-cRLReasons";
value(?'id-ce-deltaCRLIndicator') -> "id-ce-deltaCRLIndicator";
value(?'id-ce-issuingDistributionPoint') -> "id-ce-issuingDistributionPoint";
value(?'id-ce-cRLNumber') -> "id-ce-cRLNumber";
value(?'id-pe-subjectInfoAccess') -> "id-pe-subjectInfoAccess";
value(?'id-pe-authorityInfoAccess') -> "id-pe-authorityInfoAccess";
value(?'id-ce-freshestCRL') -> "id-ce-freshestCRL";
value(?'id-ce-inhibitAnyPolicy') -> "id-ce-inhibitAnyPolicy";
value(?'id-kp-OCSPSigning') -> "id-kp-OCSPSigning";
value(?'id-kp-timeStamping') -> "id-kp-timeStamping";
value(?'id-kp-emailProtection') -> "id-kp-emailProtection";
value(?'id-kp-codeSigning') -> "id-kp-codeSigning";
value(?'id-kp-clientAuth') -> "id-kp-clientAuth";
value(?'id-kp-serverAuth') -> "id-kp-serverAuth";
value(?'anyExtendedKeyUsage') -> "anyExtendedKeyUsage";
value(?'id-ce-extKeyUsage') -> "id-ce-extKeyUsage";
value(?'id-ce-cRLDistributionPoints') -> "id-ce-cRLDistributionPoints";
value(?'id-ce-policyConstraints') -> "id-ce-policyConstraints";
value(?'id-ce-nameConstraints') -> "id-ce-nameConstraints";
value(?'id-ce-basicConstraints') -> "id-ce-basicConstraints";
value(?'id-ce-subjectDirectoryAttributes') -> "id-ce-subjectDirectoryAttributes";
value(?'id-ce-issuerAltName') -> "id-ce-issuerAltName";
value(?'id-ce-subjectAltName') -> "id-ce-subjectAltName";
value(?'id-ce-policyMappings') -> "id-ce-policyMappings";
value(?'anyPolicy') -> "anyPolicy";
value(?'id-ce-certificatePolicies') -> "id-ce-certificatePolicies";
value(?'id-ce-privateKeyUsagePeriod') -> "id-ce-privateKeyUsagePeriod";
value(?'id-ce-keyUsage') -> "id-ce-keyUsage";
value(?'id-ce-subjectKeyIdentifier') -> "id-ce-subjectKeyIdentifier";
value(?'id-ce-authorityKeyIdentifier') -> "id-ce-authorityKeyIdentifier";
value(?'id-ce') -> "id-ce";
value(?'id-extensionReq') -> "id-extensionReq";
value(?'id-transId') -> "id-transId";
value(?'id-recipientNonce') -> "id-recipientNonce";
value(?'id-senderNonce') -> "id-senderNonce";
value(?'id-failInfo') -> "id-failInfo";
value(?'id-pkiStatus') -> "id-pkiStatus";
value(?'id-messageType') -> "id-messageType";
value(?'id-attributes') -> "id-attributes";
value(?'id-pki') -> "id-pki";
value(?'id-VeriSign') -> "id-VeriSign";
value(?'encryptedData') -> "encryptedData";
value(?'digestedData') -> "digestedData";
value(?'signedAndEnvelopedData') -> "signedAndEnvelopedData";
value(?'envelopedData') -> "envelopedData";
value(?'signedData') -> "signedData";
value(?'data') -> "data";
value(?'pkcs-7') -> "pkcs-7";
value(?'pkcs-9-at-counterSignature') -> "pkcs-9-at-counterSignature";
value(?'pkcs-9-at-signingTime') -> "pkcs-9-at-signingTime";
value(?'pkcs-9-at-messageDigest') -> "pkcs-9-at-messageDigest";
value(?'pkcs-9-at-contentType') -> "pkcs-9-at-contentType";
value(?'pkcs-9') -> "pkcs-9";
value(?'pkcs-9-at-extensionRequest') -> "pkcs-9-at-extensionRequest";
value(?'pkcs-9-at-challengePassword') -> "pkcs-9-at-challengePassword";
value(?'brainpoolP512t1') -> "brainpoolP512t1";
value(?'brainpoolP512r1') -> "brainpoolP512r1";
value(?'brainpoolP384t1') -> "brainpoolP384t1";
value(?'brainpoolP384r1') -> "brainpoolP384r1";
value(?'brainpoolP320t1') -> "brainpoolP320t1";
value(?'brainpoolP320r1') -> "brainpoolP320r1";
value(?'brainpoolP256t1') -> "brainpoolP256t1";
value(?'brainpoolP256r1') -> "brainpoolP256r1";
value(?'brainpoolP224t1') -> "brainpoolP224t1";
value(?'brainpoolP224r1') -> "brainpoolP224r1";
value(?'brainpoolP192t1') -> "brainpoolP192t1";
value(?'brainpoolP192r1') -> "brainpoolP192r1";
value(?'brainpoolP160t1') -> "brainpoolP160t1";
value(?'brainpoolP160r1') -> "brainpoolP160r1";
value(?'versionOne') -> "versionOne";
value(?'ellipticCurveRFC5639') -> "ellipticCurveRFC5639";
value(?'ecStdCurvesAndGeneration') -> "ecStdCurvesAndGeneration";
value(?'ub-x121-address-length') -> "ub-x121-address-length";
value(?'ub-unformatted-address-length') -> "ub-unformatted-address-length";
value(?'ub-terminal-id-length') -> "ub-terminal-id-length";
value(?'ub-surname-length') -> "ub-surname-length";
value(?'ub-pseudonym-universal') -> "ub-pseudonym-universal";
value(?'ub-pseudonym') -> "ub-pseudonym";
value(?'ub-pds-physical-address-lines') -> "ub-pds-physical-address-lines";
value(?'ub-pds-parameter-length') -> "ub-pds-parameter-length";
value(?'ub-organizational-units') -> "ub-organizational-units";
value(?'ub-numeric-user-id-length') -> "ub-numeric-user-id-length";
value(?'ub-initials-length') -> "ub-initials-length";
value(?'ub-generation-qualifier-length') -> "ub-generation-qualifier-length";
value(?'ub-e163-4-number-length') -> "ub-e163-4-number-length";
value(?'ub-domain-defined-attribute-type-length') -> "ub-domain-defined-attribute-type-length";
value(?'ub-country-name-alpha-length') -> "ub-country-name-alpha-length";
value(?'ub-emailaddress-length') -> "ub-emailaddress-length";
value(?'ub-serial-number') -> "ub-serial-number";
value(?'ub-name-utf8') -> "ub-name-utf8";
value(?'ub-name-printable') -> "ub-name-printable";
value(?'ub-name') -> "ub-name";
value(?'terminal-type') -> "terminal-type";
value(?'extended-network-address') -> "extended-network-address";
value(?'local-postal-attributes') -> "local-postal-attributes";
value(?'unique-postal-name') -> "unique-postal-name";
value(?'poste-restante-address') -> "poste-restante-address";
value(?'post-office-box-address') -> "post-office-box-address";
value(?'street-address') -> "street-address";
value(?'physical-delivery-organization-name') -> "physical-delivery-organization-name";
value(?'physical-delivery-personal-name') -> "physical-delivery-personal-name";
value(?'extension-OR-address-components') -> "extension-OR-address-components";
value(?'physical-delivery-office-number') -> "physical-delivery-office-number";
value(?'physical-delivery-office-name') -> "physical-delivery-office-name";
value(?'postal-code') -> "postal-code";
value(?'pds-name') -> "pds-name";
value(?'common-name') -> "common-name";
value(?'id-emailAddress') -> "id-emailAddress";
value(?'id-domainComponent') -> "id-domainComponent";
value(?'id-at-pseudonym') -> "id-at-pseudonym";
value(?'id-at-serialNumber') -> "id-at-serialNumber";
value(?'id-at-countryName') -> "id-at-countryName";
value(?'id-at-dnQualifier') -> "id-at-dnQualifier";
value(?'id-at-title') -> "id-at-title";
value(?'id-at-organizationalUnitName') -> "id-at-organizationalUnitName";
value(?'id-at-organizationName') -> "id-at-organizationName";
value(?'id-at-stateOrProvinceName') -> "id-at-stateOrProvinceName";
value(?'id-at-localityName') -> "id-at-localityName";
value(?'id-at-commonName') -> "id-at-commonName";
value(?'id-at-generationQualifier') -> "id-at-generationQualifier";
value(?'id-at-initials') -> "id-at-initials";
value(?'id-at-givenName') -> "id-at-givenName";
value(?'id-at-surname') -> "id-at-surname";
value(?'id-at-name') -> "id-at-name";
value(?'id-at') -> "id-at";
value(?'id-ad-caRepository') -> "id-ad-caRepository";
value(?'id-ad-timeStamping') -> "id-ad-timeStamping";
value(?'id-ad-caIssuers') -> "id-ad-caIssuers";
value(?'id-ad-ocsp') -> "id-ad-ocsp";
value(?'id-qt-unotice') -> "id-qt-unotice";
value(?'id-qt-cps') -> "id-qt-cps";
value(?'id-ad') -> "id-ad";
value(?'id-kp') -> "id-kp";
value(?'id-qt') -> "id-qt";
value(?'id-pe') -> "id-pe";
value(?'id-pkix') -> "id-pkix";
value(_) -> "unknown".

sigalg(?'id-dsa-with-sha1') ->
    "dsa-with-sha1";
sigalg(?'id-dsaWithSHA1') ->
    "dsaWithSHA1";
sigalg(?'md2WithRSAEncryption') ->
    "md2WithRSAEncryption";
sigalg(?'md5WithRSAEncryption') ->
    "md5WithRSAEncryption";
sigalg(?'sha1WithRSAEncryption') ->
    "sha1WithRSAEncryption";
sigalg(?'sha-1WithRSAEncryption') ->
    "sha-1WithRSAEncryption";
sigalg(?'sha224WithRSAEncryption') ->
    "sha224WithRSAEncryption";
sigalg(?'sha256WithRSAEncryption') ->
    "sha256WithRSAEncryption";
sigalg(?'sha512WithRSAEncryption') ->
    "sha512WithRSAEncryption";
sigalg(?'ecdsa-with-SHA1') ->
    "ecdsa-with-SHA1";
sigalg(Alg) ->
    {DigestType, SignatureType} = public_key:pkix_sign_types(Alg),
    lists:concat([DigestType, "/", SignatureType]).
