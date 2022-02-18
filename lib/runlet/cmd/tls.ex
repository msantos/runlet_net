defmodule Runlet.Cmd.TLS do
  @moduledoc "Display information about a TLS server"

  @doc """
  Displays TLS protocol, cipher suite and certificate details

  Args:

    "1.1.1.1"
    "1.1.1.1 1234"
    "1.1.1.1:1234"
  """
  @spec exec(binary) :: Enumerable.t()
  def exec(address) do
    {ip, port} =
      case Regex.split(~r/[:\s]/, address, trim: true) do
        [i, p] -> {i, p}
        [i] -> {i, "443"}
      end

    exec(ip, String.to_integer(port))
  end

  @doc """
  Displays TLS protocol, cipher suite and certificate details

  Args:

    "1.1.1.1" 443
  """
  @spec exec(binary, 0..0xFFFF) :: Enumerable.t()
  def exec(ip, port) do
    pid = self()

    fun = fn cert, event, state ->
      Kernel.send(pid, {:runlet_cmd_tls, event, cert})
      {:valid, state}
    end

    response =
      case :ssl.connect(
             String.to_charlist(ip),
             port,
             [
               verify_fun: {fun, []},
               ciphers: :ssl.cipher_suites(:all, :"tlsv1.2")
             ],
             5000
           ) do
        {:ok, s} ->
          info = connection_information(s)
          _ = :ssl.close(s)
          cert = chain()
          [info | cert]

        error ->
          [inspect(error)]
      end

    response
    |> Enum.map(fn t ->
      %Runlet.Event{
        event: %Runlet.Event.Stdout{
          host: "#{ip}:#{port}",
          service: "tls",
          description: t
        },
        query: "tls #{ip}:#{port}"
      }
    end)
  end

  def connection_information(s) do
    t =
      case :ssl.connection_information(s, [:protocol, :cipher_suite]) do
        {:ok, info} -> info
        error -> error
      end

    inspect(t)
  end

  def format(x509) do
    """
    Data:
      version: #{Kernel.get_in(x509, [:data, :version])}
      serialNumber: #{x509 |> Kernel.get_in([:data, :serialNumber]) |> serial_number()}

    Issuer:
      #{Regex.replace(~r/[^ -~\\\n]/,
    x509 |> Kernel.get_in([:issuer]) |> to_string,
    "")}

    Validity:
      notBefore: #{Kernel.get_in(x509, [:validity, :notBefore])}
      notAfter: #{Kernel.get_in(x509, [:validity, :notAfter])}

    Subject:
      #{Regex.replace(~r/[^ -~\\\n]/,
    x509 |> Kernel.get_in([:subject]) |> to_string,
    "")}
     
    Signature Algorithm:
      #{Kernel.get_in(x509, [:signatureAlgorithm])}
    """
  end

  defp chain(), do: chain([])

  defp chain(state) do
    receive do
      {:runlet_cmd_tls, {:bad_cert, _}, x509} ->
        cert = x509 |> :runlet_x509.info() |> format()
        chain([cert | state])

      {:runlet_cmd_tls, :valid, x509} ->
        cert = x509 |> :runlet_x509.info() |> format()
        chain([cert | state])

      {:runlet_cmd_tls, :valid_peer, x509} ->
        cert = x509 |> :runlet_x509.info() |> format()
        chain([cert | state])

      {:runlet_cmd_tls, {:extension, _}, _x509} ->
        chain(state)

      error ->
        [inspect(error) | state]
    after
      0 -> state |> Enum.reverse()
    end
  end

  defp serial_number(n) when n < 0xFF do
    serial =
      n
      |> :erlang.integer_to_list(16)
      |> to_string()

    "#{n} (0x#{serial})"
  end

  defp serial_number(n) when is_integer(n) do
    n
    |> :erlang.integer_to_list(16)
    |> to_string()
    |> leftpad()
    |> String.split("", trim: true)
    |> Enum.chunk_every(2)
    |> Enum.join(":")
  end

  defp leftpad(x) when is_binary(x),
    do:
      String.pad_leading(
        x,
        byte_size(x) + rem(byte_size(x), 2),
        "0"
      )
end
