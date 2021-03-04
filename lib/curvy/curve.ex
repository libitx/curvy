defmodule Curvy.Curve do
  @moduledoc """
  Describes the secp256k1 elliptic curve.
  """
  alias Curvy.Point

  @typedoc "ECDSA Curve Parameters"
  @type t :: %{
    p: integer,
    a: integer,
    b: integer,
    G: Point.t,
    n: integer,
    h: integer
  }

  @secp256k1 %{
    p: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    a: 0x0000000000000000000000000000000000000000000000000000000000000000,
    b: 0x0000000000000000000000000000000000000000000000000000000000000007,
    G: %Point{
      x: 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
      y: 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
    },
    n: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
    h: 0x01
  }


  @doc """
  Returns the secp256k1 curve parameters.
  """
  @spec secp256k1() :: t
  def secp256k1(), do: @secp256k1

end
