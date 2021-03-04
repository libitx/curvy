defmodule Curvy.MixProject do
  use Mix.Project

  def project do
    [
      app: :curvy,
      version: "0.1.0",
      elixir: "~> 1.11",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      name: "Curvy",
      description: "Signatures and Bitcoin flavoured crypto written in pure Elixir.",
      source_url: "https://github.com/libitx/curvy",
      docs: [
        main: "Curvy"
      ],
      package: [
        name: "curvy",
        files: ~w(lib .formatter.exs mix.exs README.md LICENSE),
        licenses: ["Apache-2.0"],
        links: %{
          "GitHub" => "https://github.com/libitx/curvy"
        }
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:crypto]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ex_doc, "~> 0.23", only: :dev, runtime: false}
    ]
  end
end
