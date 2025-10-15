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

value(v) when is_atom(v) -> atom_to_list(v);
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
