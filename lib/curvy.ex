defmodule Curvy do
  @moduledoc """
  ![Curvy](https://github.com/libitx/curvy/raw/master/media/poster.png)

  ![License](https://img.shields.io/github/license/libitx/curvy?color=informational)

  Signatures and Bitcoin flavoured crypto written in pure Elixir. Curvy is an
  implementation of `secp256k1`, an elliptic curve that can be used in signature
  schemes, asymmetric encryption and ECDH shared secrets.

  ## Highlights

  * Supports deterministic ECDSA signatures as per [RFC 6979](https://tools.ietf.org/html/rfc6979)
  * Fast ECDSA cryptography using Jacobian Point mathematics
  * Securely generate random ECDSA keypairs
  * Compute ECDH shared secrets
  * Zero dependencies, pure Elixir

  ## Installation

  The package can be installed by adding `curvy` to your list of dependencies in
  `mix.exs`.

  def deps do
    [
      {:curvy, "~> 0.1"}
    ]
  end

  ## Usage

  ### 1. Key generation

  Create random ECDSA keypairs.

      iex> key = Curvy.generate_key()
      %Curvy.Key{
        crv: :secp256k1,
        point: %Curvy.Point{},
        private_key: <<>>
      }

  [`ECDSA Keypairs`](`t:Curvy.Key.t`) can by converted to public and private key
  binaries.

      iex> Curvy.Key.to_privkey(key)
      <<privkey::binery-size(32)>>

      iex> Curvy.Key.to_pubkey(key)
      <<privkey::binary-size(33)>>

      iex> Curvy.Key.to_pubkey(key, compressed: false)
      <<privkey::binary-size(65)>>

  ### 2. ECDH shared secrets

  ECDH shared secrets are computed by multiplying a public key with a private
  key. The operation yields the same result in both directions.

      iex> s1 = Curvy.get_shared_secret(key1, key2)
      iex> s2 = Curvy.get_shared_secret(key2, key1)
      iex> s1 == s2
      true

  ### 3. Sign messages

  Sign arbitrary messages with a private key. Signatures are deterministic as
  per [RFC 6979](https://tools.ietf.org/html/rfc6979).

      iex> sig = Curvy.sign("hello", key)
      <<sig::binary-size(71)>>

      iex> sig = Curvy.sign("hello", compact: true)
      <<sig::binary-size(65)>>

      iex> sig = Curvy.sign("hello", compact: true, encoding: :base64)
      "IEnXUDXZ3aghwXaq1zu9ax2zJj7N+O4gGREmWBmrldwrIb9B7QuicjwPrrv3ocPpxYO7uCxcw+DR/FcHR9b/YjM="

  ### 4. Verify signatures

  Verify a signature against the message and a public key.

      iex> sig = Curvy.verify(sig, "hello", key)
      true

      iex> sig = Curvy.verify(sig, "hello", wrongkey)
      false

      # Returns :error if the signature cannot be decoded
      iex> sig = Curvy.verify("notasig", "hello", key)
      :error

  """
  use Bitwise, only_operators: true
  alias Curvy.{Curve, Key, Point, Signature}
  import Curvy.Util, only: [encode: 2, decode: 2, inv: 2, mod: 2]

  @crv Curve.secp256k1


  @doc """
  Creates a new random ESCDA keypair.
  """
  @spec generate_key() :: Key.t
  def generate_key(), do: Key.generate()


  @doc """
  Computes an ECDH shared secret from the first given key's private key and
  the second's public key.

  Returns a 32 byte binary.

  ## Accepted options

  * `:encoding` - Optionally encode the returned secret as `:base64` or `:hex`.
  """
  @spec get_shared_secret(Key.t | binary, Key.t | binary) :: binary
  def get_shared_secret(privkey, pubkey, opts \\ [])

  def get_shared_secret(privkey, pubkey, opts) when is_binary(privkey),
    do: get_shared_secret(Key.from_privkey(privkey), pubkey, opts)

  def get_shared_secret(privkey, pubkey, opts) when is_binary(pubkey),
    do: get_shared_secret(privkey, Key.from_pubkey(pubkey), opts)

  def get_shared_secret(%Key{privkey: <<d::big-size(256)>>}, %Key{point: point}, opts) do
    encoding = Keyword.get(opts, :encoding)
    point
    |> Point.mul(d)
    |> Map.get(:x)
    |> :binary.encode_unsigned()
    |> encode(encoding)
  end


  @doc """
  Signs the message with the given private key.

  Returns a signature binary.

  ## Accepted options

  * `:hash` - Digest algorithm to hash the message with. Default is `:sha256`.
  * `:normalize` - Normalize the signature by enforcing low-S. Default is `true`.
  * `:compact` - Return a compact 65 byte signature. Default is `false`.
  * `:encoding` - Optionally encode the returned signature as `:base64` or `:hex`.
  * `:recovery` - Return the signature in a tuple paired with a recovery ID. Default is `false`.
  """
  @spec sign(binary, Key.t | binary, keyword) :: binary
  def sign(message, privkey, opts \\ [])

  def sign(message, %Key{privkey: privkey}, opts) when is_binary(privkey),
    do: sign(message, privkey, opts)

  def sign(message, <<d::big-size(256)>>, opts) do
    digest = Keyword.get(opts, :hash, :sha256)
    normalize = Keyword.get(opts, :normalize, true)
    compact = Keyword.get(opts, :compact, false)
    encoding = Keyword.get(opts, :encoding)
    recovery = Keyword.get(opts, :recovery)

    {q, r, s} = get_qrs(message, digest, d)
    recovery_id = if q.x == r,
      do: 0 ||| (q.y &&& 1),
      else: 2 ||| (q.y &&& 1)

    %Signature{r: r, s: s}
    |> maybe_normalize(normalize)
    |> maybe_compact(recovery_id, compact)
    |> encode(encoding)
    |> maybe_recovery(recovery_id, recovery)
  end


  @doc """
  Verifies the signature against the given message and public key.

  Returns a boolean.

  ## Accepted options

  * `:encoding` - Optionally decode the given signature as `:base64` or `:hex`.
  """
  @spec verify(Signature.t | binary, binary, Key.t | binary, keyword) :: boolean
  def verify(sig, message, pubkey, opts \\ [])

  def verify(sig, message, pubkey, opts) when is_binary(pubkey),
    do: verify(sig, message, Key.from_pubkey(pubkey), opts)

  def verify(sig, message, %Key{} = pubkey, opts) when is_binary(sig) do
    encoding = Keyword.get(opts, :encoding)
    with {:ok, sig} <- decode(sig, encoding),
         %Signature{} = sig <- Signature.parse(sig)
    do
      verify(sig, message, pubkey, opts)
    end
  end

  def verify(%Signature{r: r, s: s}, message, %Key{point: point}, opts) do
    digest = Keyword.get(opts, :hash, :sha256)
    e = message
    |> hash_message(digest)
    |> :binary.decode_unsigned()

    i = inv(s, @crv.n)

    p = Point.mul(@crv[:G], mod(e * i, @crv.n))
    q = Point.mul(point, mod(r * i, @crv.n))

    Point.add(p, q)
    |> Map.get(:x)
    |> Kernel.==(r)
  end


  # Returns the QRS values for the message and privkey
  defp get_qrs(message, digest, d) do
    message
    |> hash_message(digest)
    |> deterministic_k(d)
  end


  # Hashes the message with the given digest algorith
  defp hash_message(message, digest) when digest in [:sha256, :sha384, :sha512],
    do: :crypto.hash(digest, message)

  defp hash_message(message, _digest), do: message


  # Implements RFC 6979 and returns QRS values from deterministically generated K
  defp deterministic_k(hash, d) do
    e = :binary.decode_unsigned(hash)
    v = :binary.copy(<<0>>, 32)
    k = :binary.copy(<<1>>, 32)
    k = :crypto.hmac(:sha256, k, <<v::binary, 0, d::big-size(256), hash::binary>>)
    v = :crypto.hmac(:sha256, k, v)
    k = :crypto.hmac(:sha256, k, <<v::binary, 1, d::big-size(256), hash::binary>>)
    v = :crypto.hmac(:sha256, k, v)

    Enum.reduce_while 0..1000, {k, v}, fn i, {k, v} ->
      if i == 1000, do: throw "Tried 1000 k values, all were invalid"
      v = :crypto.hmac(:sha256, k, v)

      case v do
        <<t::big-size(256)>> when 0 < t and t < @crv.n ->
          q = Point.mul(@crv[:G], t)
          r = mod(q.x, @crv.n)
          s = (inv(t, @crv.n) * (e + r * d)) |> mod(@crv.n)

          if r == 0 or s == 0,
            do: {:cont, {k, v}},
            else: {:halt, {q, r, s}}

        _ ->
          k = :crypto.hmac(:sha256, k, <<v::binary, 0>>)
          v = :crypto.hmac(:sha256, k, v)
          {:cont, {k, v}}
      end
    end
  end


  # Normalizes the given signature if opted for
  defp maybe_normalize(%Signature{} = sig, b) when b in [false, nil], do: sig
  defp maybe_normalize(%Signature{} = sig, _b), do: Signature.normalize(sig)


  # Returns compact or der encoded signature
  defp maybe_compact(%Signature{} = sig, _rec_id, b) when b in [false, nil],
    do: Signature.to_der(sig)
  defp maybe_compact(%Signature{} = sig, rec_id, _b),
    do: Signature.to_compact(sig, rec_id)


  # Returns the signature with recovery is of opted for
  defp maybe_recovery(sig, rec_id, true), do: {sig, rec_id}
  defp maybe_recovery(sig, _rec_id, _b), do: sig

end
