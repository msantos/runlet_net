defmodule RunletCmdTLSTest do
  use ExUnit.Case

  url = Runlet.Cmd.TLS.exec("httpbin.org")
  urlport = Runlet.Cmd.TLS.exec("httpbin.org:443")
  arity2 = Runlet.Cmd.TLS.exec("httpbin.org", 443)

  # ensure bad certificates can be dumped
  untrusted_root = Runlet.Cmd.TLS.exec("untrusted-root.badssl.com")
  expired = Runlet.Cmd.TLS.exec("expired.badssl.com")
  sha1 = Runlet.Cmd.TLS.exec("sha1-intermediate.badssl.com")
  des3 = Runlet.Cmd.TLS.exec("3des.badssl.com")

  assert [
           %Runlet.Event{
             attr: %{},
             event: %Runlet.Event.Stdout{
               description: _,
               host: "httpbin.org:443",
               service: "tls",
               time: ""
             },
             query: "tls httpbin.org:443"
           }
           | _
         ] = url

  assert [
           %Runlet.Event{
             attr: %{},
             event: %Runlet.Event.Stdout{
               description: _,
               host: "httpbin.org:443",
               service: "tls",
               time: ""
             },
             query: "tls httpbin.org:443"
           }
           | _
         ] = urlport

  assert [
           %Runlet.Event{
             attr: %{},
             event: %Runlet.Event.Stdout{
               description: _,
               host: "httpbin.org:443",
               service: "tls",
               time: ""
             },
             query: "tls httpbin.org:443"
           }
           | _
         ] = arity2

  assert [
           %Runlet.Event{
             attr: %{},
             event: %Runlet.Event.Stdout{
               description: <<"[protocol: :\"tlsv", _::binary>>,
               host: "untrusted-root.badssl.com:443",
               service: "tls",
               time: ""
             },
             query: "tls untrusted-root.badssl.com:443"
           }
           | _
         ] = untrusted_root

  assert [
           %Runlet.Event{
             attr: %{},
             event: %Runlet.Event.Stdout{
               description: <<"[protocol: :\"tlsv", _::binary>>,
               host: "expired.badssl.com:443",
               service: "tls",
               time: ""
             },
             query: "tls expired.badssl.com:443"
           }
           | _
         ] = expired

  assert [
           %Runlet.Event{
             attr: %{},
             event: %Runlet.Event.Stdout{
               description: <<"[protocol: :\"tlsv", _::binary>>,
               host: "sha1-intermediate.badssl.com:443",
               service: "tls",
               time: ""
             },
             query: "tls sha1-intermediate.badssl.com:443"
           }
           | _
         ] = sha1

  assert [
           %Runlet.Event{
             attr: %{},
             event: %Runlet.Event.Stdout{
               description: <<"[protocol: :\"tlsv", _::binary>>,
               host: "3des.badssl.com:443",
               service: "tls",
               time: ""
             },
             query: "tls 3des.badssl.com:443"
           }
           | _
         ] = des3
end
