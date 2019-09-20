defmodule Runlet.Cmd.HTTP do
  @moduledoc "Retrieve an HTTP URL"

  @doc """
  Retrieves an http URL.
  """
  @spec exec(binary) :: Enumerable.t()
  def exec(url) do
    response =
      case :httpc.request(url) do
        {:ok, {_response, _headers, body}} ->
          body

        error ->
          inspect(error)
      end

    [
      %Runlet.Event{
        event: %Runlet.Event.Stdout{
          host: "#{node()}",
          service: "http",
          description: response
        },
        query: "http #{url}"
      }
    ]
  end
end
