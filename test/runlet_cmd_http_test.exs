defmodule RunletCmdHTTPTest do
  use ExUnit.Case

  test "http: request URL" do
    result = Runlet.Cmd.HTTP.exec("http://httpbin.org/status/200")

    assert [
             %Runlet.Event{
               attr: %{},
               event: %Runlet.Event.Stdout{
                 description: [],
                 host: "nonode@nohost",
                 service: "http",
                 time: ""
               },
               query: "http http://httpbin.org/status/200"
             }
           ] = result
  end
end
