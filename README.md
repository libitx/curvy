# Curvy

Curvy is a pure Elixir implementation of `secp256k1`, an elliptic curve that can be used in signature schemes, asymmetric encryption and ECDH shared secrets.

`secp256k1` is used in Bitcoin, and Curvy exposes a handful of functions to help with common Bitcoin app use cases.

## Highlights

* Supports deterministic ECDSA signatures as per [RFC 6979](https://tools.ietf.org/html/rfc6979)
* Fast ECDSA cryptography using Jacobian Point mathematics
* Securely generate random ECDSA keypairs
* Compute ECDH shared secrets
* Zero dependencies, pure Elixir

## Installation

The package can be installed by adding `curvy` to your list of dependencies in `mix.exs`.

```elixir
def deps do
  [
    {:curvy, "~> 0.1"}
  ]
end
```

## Usage

For further examples, refer to the [full documentation](https://hexdocs.pm/curvy).

### 1. Key generation

Create random ECDSA keypairs.

```elixir
iex> key = Curvy.generate_key()
%Curvy.Key{
  crv: :secp256k1,
  point: %Curvy.Point{},
  private_key: <<>>
}
```

ECDSA Keypairs can by converted to public and private key binaries.

```elixir
iex> Curvy.Key.to_privkey(key)
<<privkey::binery-size(32)>>

iex> Curvy.Key.to_pubkey(key)
<<privkey::binary-size(33)>>

iex> Curvy.Key.to_pubkey(key, compressed: false)
<<privkey::binary-size(65)>>
```

### 2. ECDH shared secrets

ECDH shared secrets are computed by multiplying a public key with a private
key. The operation yields the same result in both directions.

```elixir
iex> s1 = Curvy.get_shared_secret(key1, key2)
iex> s2 = Curvy.get_shared_secret(key2, key1)
iex> s1 == s2
true
```

### 3. Sign messages

Sign arbitrary messages with a private key. Signatures are deterministic as per [RFC 6979](https://tools.ietf.org/html/rfc6979).

```elixir
iex> sig = Curvy.sign("hello", key)
<<sig::binary-size(71)>>

iex> sig = Curvy.sign("hello", compact: true)
<<sig::binary-size(65)>>

iex> sig = Curvy.sign("hello", compact: true, encoding: :base64)
"IEnXUDXZ3aghwXaq1zu9ax2zJj7N+O4gGREmWBmrldwrIb9B7QuicjwPrrv3ocPpxYO7uCxcw+DR/FcHR9b/YjM="
```

### 4. Verify signatures

Verify a signature against the message and a public key.

```elixir
iex> sig = Curvy.verify(sig, "hello", key)
true

iex> sig = Curvy.verify(sig, "hello", wrongkey)
false

# Returns :error if the signature cannot be decoded
iex> sig = Curvy.verify("notasig", "hello", key)
:error
```

For more examples, refer to the [full documentation](https://hexdocs.pm/curvy).

## Disclaimer

The are many articles published warning that you should never try to implement well-known (and known to be secure) crypto algorithms yourself. Well guess what, that's exactly what I've done here. I am **not** a cryptographer nor a mathmetician. If you're after the most performant and battle tested Bitcoin library, use the [`libsecp256k1`](https://hex.pm/packages/libsecp256k1) NIF bindings.

This library offers a simpler and smaller interface for common functionality. Being writting purely in Elixir without any dependencies, it is a lighter-weight option without the compilation complexities the NIF bindings may bring.

I am grateful to the authors of the following open source libraries I have referred to extensively in creating this library:

* [noble-secp256k1](https://github.com/paulmillr/noble-secp256k1) - JS
* [starbank-ecdsa](https://github.com/starkbank/ecdsa-elixir) - Elixir
* [bsv](https://github.com/moneybutton/bsv) - JS

## License

Txpost is open source and released under the [Apache-2 License](https://github.com/libitx/curvy/blob/master/LICENSE).

© Copyright 2021 [Chronos Labs Ltd](https://www.chronoslabs.net).