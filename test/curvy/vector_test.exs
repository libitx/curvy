defmodule Curvy.VectorTest do
  use ExUnit.Case, async: true

  @rfc6979_vectors File.read!("test/vectors/ecdsa.json")
    |> Jason.decode!()

  @ecdh_vectors File.read!("test/vectors/ecdh.json")
    |> Jason.decode!()
    |> Map.get("testGroups")
    |> List.first()
    |> Map.get("tests")

  @ecdh_valid Enum.filter(@ecdh_vectors, & &1["result"] == "valid")

  describe "Curvy.sign/3 rfc6979 vectors" do
    for {vector, i} <- Enum.with_index(@rfc6979_vectors["valid"]) do
      test "passes valid vector: #{i}" do
        %{"m" => m, "d" => d, "signature" => sig} = unquote(Macro.escape(vector))
        <<_prefix, res::binary>> = Curvy.sign(Base.decode16!(m, case: :lower), Base.decode16!(d, case: :lower), hash: false, compact: true)
        assert res == Base.decode16!(sig, case: :lower)
      end
    end
  end

  describe "Curvy.get_shared_secret/3 test vectors" do
    for {vector, i} <- Enum.with_index(@ecdh_valid) do
      test "passes valid vector: #{i}" do
        v = unquote(Macro.escape(vector))
        privkey = v["private"] |> Base.decode16!(case: :lower) |> ecdh_privkey()
        pubkey  = v["public"] |> Base.decode16!(case: :lower) |> ecdh_pubkey()
        assert Curvy.get_shared_secret(privkey, pubkey, encoding: :hex) == v["shared"]
      end
    end
  end

  def ecdh_privkey(<<_prefix, privkey::binary-size(32)>>), do: privkey

  def ecdh_privkey(privkey) do
    :binary.copy(<<0>>, 32-byte_size(privkey))
    |> Kernel.<>(privkey)
  end

  def ecdh_pubkey(<<_der::binary-size(23), pubkey::binary>>), do: pubkey

end
