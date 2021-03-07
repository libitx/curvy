defmodule Curvy.Util do
  @moduledoc """
  Utility module for common and shared functions.
  """

  @doc """
  Decodes the given binary with the specified encoding scheme.

  Accepts `:base64` or `:hex`, or will return the binary as is.
  """
  @spec decode(binary, atom) :: {:ok, binary} | {:error, any}
  def decode(data, enc) when enc in [:base64, :b64], do: Base.decode64(data)
  def decode(data, :hex), do: Base.decode16(data, case: :mixed)
  def decode(data, _), do: {:ok, data}


  @doc """
  Encodes the given binary with the specified encoding scheme.

  Accepts `:base64` or `:hex`, or will return the binary as is.
  """
  @spec encode(binary, atom) :: binary
  def encode(data, enc) when enc in [:base64, :b64], do: Base.encode64(data)
  def encode(data, :hex), do: Base.encode16(data, case: :lower)
  def encode(data, _), do: data


  @doc """
  Invert operation.
  """
  @spec inv(integer, integer) :: integer
  def inv(x, _n) when x == 0, do: 0
  def inv(x, n), do: inv_op(1, 0, mod(x, n), n)


  @doc """
  Inverse power operation.
  """
  @spec ipow(integer, integer) :: integer
  def ipow(base, p, acc \\ 1)
  def ipow(base, p, acc) when p > 0, do: ipow(base, p - 1, base * acc)
  def ipow(_base, _p, acc), do: acc


  @doc """
  Modulo operation. Returns the remainder after x is divided by n.
  """
  @spec mod(integer, integer) :: integer
  def mod(x, n), do: rem(x, n) |> correct_neg_mod(n)


  # Correct mod if negative
  defp correct_neg_mod(r, n) when r < 0, do: r + n
  defp correct_neg_mod(r, _n), do: r


  # Recursive inv function
  defp inv_op(lm, hm, low, high) when low > 1 do
    r = div(high, low)
    inv_op(hm - lm * r, lm, high - low * r, low)
  end

  defp inv_op(lm, _hm, _low, _high), do: lm

end
