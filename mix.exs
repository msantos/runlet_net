defmodule RunletNet.Mixfile do
  use Mix.Project

  def project do
    [
      app: :runlet_net,
      version: "1.0.4",
      elixir: "~> 1.9",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      description: "Miscellaneous network related commands for runlets",
      deps: deps(),
      package: package(),
      dialyzer: [
        list_unused_filters: true,
        flags: [
          "-Wunmatched_returns",
          :error_handling,
          :race_conditions,
          :underspecs
        ]
      ]
    ]
  end

  # Configuration for the OTP application
  #
  # Type "mix help compile.app" for more information
  def application do
    #  [applications: [:logger]]
    [extra_applications: [:inets, :ssl]]
  end

  defp package do
    [
      licenses: ["ISC"],
      links: %{github: "https://github.com/msantos/runlet_net"}
    ]
  end

  # Dependencies can be Hex packages:
  #
  #   {:mydep, "~> 0.3.0"}
  #
  # Or git/path repositories:
  #
  #   {:mydep, git: "https://github.com/elixir-lang/mydep.git", tag: "0.1.0"}
  #
  # Type "mix help deps" for more examples and options
  defp deps do
    [
      {:runlet, "~> 1.2"},
      {:credo, "~> 1.6", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.28", only: :dev, runtime: false},
      {:dialyxir, "~> 1.1", only: [:dev], runtime: false},
      {:gradient, github: "esl/gradient", only: [:dev], runtime: false}
    ]
  end
end
