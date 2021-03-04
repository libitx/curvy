defmodule Curvy.Signature do
  @moduledoc """
  Module for converting signature R and S values to DER encoded or compact
  binaries.
  """
  use Bitwise, only_operators: true
  alias Curvy.Curve

  defstruct r: nil,
            s: nil

  @typedoc "ECDSA Signature"
  @type t :: %__MODULE__{
    r: integer,
    s: integer
  }

  @crv Curve.secp256k1


  @doc """
  Parsed the given binary signature in a [`Signature`](`t:t`) struct.

  Parsed DER encoded and compact signatures. Returns `:error` if unable to parse.
  """
  @spec parse(binary) :: t | :error
  def parse(<<0x30, _len, 0x02, rlen, rbin::bytes-size(rlen), 0x02, slen, sbin::bytes-size(slen)>>) do
    %__MODULE__{
      r: :binary.decode_unsigned(rbin),
      s: :binary.decode_unsigned(sbin)
    }
  end

  def parse(<<_prefix::integer, r::big-size(256), s::big-size(256)>>),
    do: %__MODULE__{r: r, s: s}

  def parse(_sig), do: :error


  @doc """
  Normalizes the signature by enforcing Low-S values.

  Returns a [`Signature`](`t:t`).

  See [BIP 62](https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki)
  for more info.
  """
  @spec normalize(t) :: t
  def normalize(%__MODULE__{s: s} = sig) do
    case s > Integer.floor_div(@crv.n, 2) do
      true ->
        Map.put(sig, :s, @crv.n - s)
      false ->
        sig
    end
  end



  @doc """
  Returns the signature as a DER-encoded binary.
  """
  @spec to_der(t) :: binary
  def to_der(%__MODULE__{r: r, s: s}, _opts \\ []) do
    rbin = der_encode_int(r)
    sbin = der_encode_int(s)
    rlen = byte_size(rbin)
    slen = byte_size(sbin)

    <<
      0x30,                 # header
      2 + rlen + 2 + slen,  # length
      0x02,                 # r header
      rlen,                 # r length
      rbin::binary,         # r
      0x02,                 # s header
      slen,                 # s length
      sbin::binary          # s
    >>
  end


  @doc """
  Returns the signature as a 65 byte compact binary.
  """
  @spec to_compact(t, integer) :: binary
  def to_compact(%__MODULE__{r: r, s: s}, recovery_id, opts \\ [])
    when recovery_id in 0..3
  do
    compressed = Keyword.get(opts, :compressed, true)

    prefix = case compressed do
      true -> recovery_id + 27 + 4
      false -> recovery_id + 27
    end

    <<
      prefix,             # recovery
      r::big-size(256),   # r
      s::big-size(256)    # s
    >>
  end


  # DER encodes the given integer
  defp der_encode_int(int) when is_integer(int) do
    <<n::integer, _::binary>> = bin = :binary.encode_unsigned(int)
    case n &&& 0x80 do
      0 -> bin
      _ -> <<0, bin::binary>>
    end
  end

end
