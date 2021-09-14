defmodule Curvy do
  @moduledoc """
  ![Curvy](https://github.com/libitx/curvy/raw/master/media/poster.png)

  ![License](https://img.shields.io/github/license/libitx/curvy?color=informational)

  Signatures and Bitcoin flavoured crypto written in pure Elixir. Curvy is an
  implementation of `secp256k1`, an elliptic curve that can be used in signature
  schemes, asymmetric encryption and ECDH shared secrets.

  ## Highlights

  * Pure Elixir implementation of `secp256k1` - no external dependencies
  * Fast ECDSA cryptography using Jacobian Point mathematics
  * Supports deterministic ECDSA signatures as per [RFC 6979](https://tools.ietf.org/html/rfc6979)
  * Securely generate random ECDSA keypairs
  * Compute ECDH shared secrets

  ## Installation

  The package can be installed by adding `curvy` to your list of dependencies in
  `mix.exs`.

      def deps do
        [
          {:curvy, "~> #{ Mix.Project.config[:version] }"}
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

  ### 2. Sign messages

  Sign arbitrary messages with a private key. Signatures are deterministic as
  per [RFC 6979](https://tools.ietf.org/html/rfc6979).

      iex> sig = Curvy.sign("hello", key)
      <<sig::binary-size(71)>>

      iex> sig = Curvy.sign("hello", compact: true)
      <<sig::binary-size(65)>>

      iex> sig = Curvy.sign("hello", compact: true, encoding: :base64)
      "IEnXUDXZ3aghwXaq1zu9ax2zJj7N+O4gGREmWBmrldwrIb9B7QuicjwPrrv3ocPpxYO7uCxcw+DR/FcHR9b/YjM="

  ### 3. Verify signatures

  Verify a signature against the message and a public key.

      iex> sig = Curvy.verify(sig, "hello", key)
      true

      iex> sig = Curvy.verify(sig, "hello", wrongkey)
      false

      # Returns :error if the signature cannot be decoded
      iex> sig = Curvy.verify("notasig", "hello", key)
      :error

  ### 4. Recover the public key from a signature

  It's possible to recover the public key from a compact signature when given
  with the signed message.

      iex> sig = Curvy.sign("hello", key, compact: true)
      iex> recovered = Curvy.recover_key(sig, "hello")
      iex> recovered.point == key.point
      true

  The same can be done with DER encoded signatures if the recovery ID is known.

      iex> {sig, recovery_id} = Curvy.sign("hello", key, recovery: true)
      iex> recovered = Curvy.recover_key(sig, "hello", recovery_id: recovery_id)
      iex> recovered.point == key.point
      true

  ### 5. ECDH shared secrets

  ECDH shared secrets are computed by multiplying a public key with a private
  key. The operation yields the same result in both directions.

      iex> s1 = Curvy.get_shared_secret(key1, key2)
      iex> s2 = Curvy.get_shared_secret(key2, key1)
      iex> s1 == s2
      true

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
    x = point
    |> Point.mul(d)
    |> Map.get(:x)
    encode(<<x::big-size(256)>>, encoding)
  end


  @doc """
  Recovers the public key from the signature and signed message.

  Returns an [`ECDSA Keypair`](`t:t`) struct, without the privkey value.

  If recovering fom a DER encoded signature, the [`Recovery ID`](`Signature.recovery_id`)
  returned from `Curvy.sign(msg, key, recovery: true)` must be passed as an
  option. If recovering from a compact signature the recovery ID is already
  encoded in the signature.

  ## Accepted options

  * `:encoding` - Optionally decode the given signature as `:base64` or `:hex`.
  * `:hash` - Digest algorithm to hash the message with. Default is `:sha256`.
  * `:recovery_id` - The signature [`Recovery ID`](`Signature.recovery_id`).
  """
  @spec recover_key(Signature.t | binary, binary, keyword) :: Key.t | :error
  def recover_key(sig, message, opts \\ [])

  def recover_key(data, message, opts) when is_binary(data) do
    encoding = Keyword.get(opts, :encoding)
    with {:ok, data} <- decode(data, encoding),
         %Signature{} = sig <- Signature.parse(data)
    do
      opts = case data do
        <<prefix, _sig::binary-size(64)>> when (prefix - 27 - 4) < 0 ->
          Keyword.put(opts, :compressed, false)
        _ ->
          opts
      end
      recover_key(sig, message, opts)
    end
  end

  def recover_key(%Signature{recid: recid} = sig, message, opts) do
    with recid when recid in 0..3 <- Keyword.get(opts, :recovery_id, recid) do
      digest = Keyword.get(opts, :hash, :sha256)
      e = message
      |> hash_message(digest)
      |> :binary.decode_unsigned()

      sig
      |> Signature.normalize()
      |> Point.from_signature(e, recid)
      |> Key.from_point(Keyword.take(opts, [:compressed]))
    else
      _ ->
        raise "Recovery ID not in range 0..3"
    end
  end


  @doc """
  Signs the message with the given private key.

  Returns a DER encoded or compact signature binary.

  ## Accepted options

  * `:hash` - Digest algorithm to hash the message with. Default is `:sha256`.
  * `:normalize` - Normalize the signature by enforcing low-S. Default is `true`.
  * `:compact` - Return a compact 65 byte signature. Default is `false`.
  * `:encoding` - Optionally encode the returned signature as `:base64` or `:hex`.
  * `:recovery` - Return the signature in a tuple paired with a recovery ID. Default is `false`.
  """
  @spec sign(binary, Key.t | binary, keyword) :: binary
  def sign(message, privkey, opts \\ [])

  def sign(message, %Key{privkey: privkey, compressed: compressed}, opts)
    when is_binary(privkey)
  do
    opts = Keyword.put_new(opts, :compressed, compressed)
    sign(message, privkey, opts)
  end

  def sign(message, <<d::big-size(256)>>, opts) do
    digest = Keyword.get(opts, :hash, :sha256)
    encoding = Keyword.get(opts, :encoding)

    {q, r, s} = get_qrs(message, digest, d)
    recid = get_recovery_id(q, r)

    sig = %Signature{r: r, s: s, recid: recid}
    |> maybe_normalize(opts)

    sig
    |> maybe_compact(opts)
    |> encode(encoding)
    |> maybe_recovery(sig, opts)
  end


  @doc """
  Verifies the signature against the given message and public key.

  Returns a boolean.

  ## Accepted options

  * `:encoding` - Optionally decode the given signature as `:base64` or `:hex`.
  * `:hash` - Digest algorithm to hash the message with. Default is `:sha256`.
  """
  @spec verify(Signature.t | binary, binary, Key.t | binary, keyword) :: boolean | :error
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
    v = :binary.copy(<<1>>, 32)
    k = :binary.copy(<<0>>, 32)
    k = :crypto.mac(:hmac, :sha256, k, <<v::binary, 0, d::big-size(256), hash::binary>>)
    v = :crypto.mac(:hmac, :sha256, k, v)
    k = :crypto.mac(:hmac, :sha256, k, <<v::binary, 1, d::big-size(256), hash::binary>>)
    v = :crypto.mac(:hmac, :sha256, k, v)

    Enum.reduce_while 0..1000, {k, v}, fn i, {k, v} ->
      if i == 1000, do: throw "Tried 1000 k values, all were invalid"
      v = :crypto.mac(:hmac, :sha256, k, v)

      case v do
        <<t::big-size(256)>> when 0 < t and t < @crv.n ->
          q = Point.mul(@crv[:G], t)
          r = mod(q.x, @crv.n)
          s = (inv(t, @crv.n) * (e + r * d)) |> mod(@crv.n)

          if r == 0 or s == 0,
            do: {:cont, {k, v}},
            else: {:halt, {q, r, s}}

        _ ->
          k = :crypto.mac(:hmac, :sha256, k, <<v::binary, 0>>)
          v = :crypto.mac(:hmac, :sha256, k, v)
          {:cont, {k, v}}
      end
    end
  end


  # Get the recovery ID from the point and R value
  defp get_recovery_id(%{x: x, y: y}, r) when x == r, do: 0 ||| (y &&& 1)
  defp get_recovery_id(%{x: _x, y: y}, _r), do: 2 ||| (y &&& 1)


  # Normalizes the given signature if opted for
  defp maybe_normalize(%Signature{} = sig, opts) do
    case Keyword.get(opts, :normalize, true) do
      opt when opt in [false, nil] ->
        sig
      _ ->
        Signature.normalize(sig)
    end
  end


  # Returns compact or der encoded signature
  defp maybe_compact(%Signature{} = sig, opts) do
    case Keyword.get(opts, :compact, false) do
      opt when opt in [false, nil] ->
        Signature.to_der(sig)
      _ ->
        Signature.to_compact(sig, Keyword.take(opts, [:compressed]))
    end
  end


  # Returns the signature with recovery is of opted for
  defp maybe_recovery(encoded_sig, %Signature{recid: recid}, opts)
    when is_integer(recid)
  do
    case Keyword.get(opts, :recovery) do
      true -> {encoded_sig, recid}
      _ -> encoded_sig
    end
  end

  defp maybe_recovery(encoded_sig, _sig, _opts), do: encoded_sig

end
