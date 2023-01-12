defmodule CurvyTest do
  use ExUnit.Case, async: true
  alias Curvy.Key

  @test_key %Key{
    point: %Curvy.Point{
      x: 4118631015477382459373946646660315625074350024199250279717429272329062331319,
      y: 66793862366389912668178571190474290679389778848647827908619288257874616811393
    },
    privkey: <<94, 192, 161, 170, 53, 38, 244, 110, 98, 81, 216, 146, 105, 34,
      164, 239, 61, 139, 33, 152, 191, 245, 56, 236, 25, 192, 99, 99, 138, 85, 5,
      185>>
  }

  @test_key_2 %Key{
    point: %Curvy.Point{
      x: 18104471324754606025397722809760948127956696160058047068016426305179077487064,
      y: 29609997689294885043479429890515147582121499892730909103923743804350436693119
    },
    privkey: <<65, 20, 145, 128, 181, 91, 11, 5, 227, 139, 223, 209, 143, 155,
      170, 148, 115, 249, 64, 53, 140, 70, 50, 140, 125, 196, 66, 64, 203, 189,
      172, 1>>
  }


  describe "generate_key/0" do
    test "returns a randomly generated key" do
      assert %Key{} = Curvy.generate_key()
    end
  end


  @test_secret <<
    241, 47, 119, 25, 77, 84, 86, 10, 220, 16, 169, 64, 156, 169, 122, 143, 210,
    62, 226, 204, 143, 254, 197, 249, 125, 57, 216, 15, 205, 25, 170, 217>>
  @test_secret_b64 "8S93GU1UVgrcEKlAnKl6j9I+4syP/sX5fTnYD80Zqtk="
  @test_secret_hex "f12f77194d54560adc10a9409ca97a8fd23ee2cc8ffec5f97d39d80fcd19aad9"

  describe "get_shared_secret/3" do
    test "returns a shared secret in the given encoding" do
      assert Curvy.get_shared_secret(@test_key, @test_key_2) == @test_secret
      assert Curvy.get_shared_secret(@test_key, @test_key_2, encoding: :base64) == @test_secret_b64
      assert Curvy.get_shared_secret(@test_key, @test_key_2, encoding: :hex) == @test_secret_hex
    end

    test "returns same result in reverse" do
      assert Curvy.get_shared_secret(@test_key_2, @test_key) == @test_secret
    end

    test "constent with built in erlang results" do
      assert :crypto.compute_key(:ecdh, Key.to_pubkey(@test_key_2), @test_key.privkey, :secp256k1) == @test_secret
      assert :crypto.compute_key(:ecdh, Key.to_pubkey(@test_key), @test_key_2.privkey, :secp256k1) == @test_secret
    end

    test "accepts binary keys" do
      assert Curvy.get_shared_secret(Key.to_privkey(@test_key), Key.to_pubkey(@test_key_2)) == @test_secret
    end
  end


  describe "recover_key/3" do
    test "recovers from a der sig if you have the recovery id" do
      {sig, recovery_id} = Curvy.sign("testing recovery", @test_key, recovery: true)
      assert %Key{point: point} = Curvy.recover_key(sig, "testing recovery", recovery_id: recovery_id)
      assert point == @test_key.point
    end

    test "recovers from a compact sig automatically" do
      sig = Curvy.sign("testing recovery", @test_key, compact: true)
      assert %Key{point: point} = Curvy.recover_key(sig, "testing recovery")
      assert point == @test_key.point
    end

    test "correctly recovers uncompressed keys" do
      test_key = Map.put(@test_key, :compressed, false)
      sig = Curvy.sign("testing recovery", test_key, compact: true)
      assert %Key{point: point, compressed: false} = Curvy.recover_key(sig, "testing recovery")
      assert point == @test_key.point
    end

    test "raises error if not a valid recovery ID" do
      assert_raise RuntimeError, "Recovery ID not in range 0..3", fn ->
        Curvy.sign("testing recovery", @test_key) |> Curvy.recover_key("testing recovery")
      end
    end
  end


  @test_sig <<
    48, 68, 2, 32, 42, 65, 162, 214, 121, 255, 204, 204, 227, 137, 211, 178, 122,
    128, 172, 232, 164, 118, 53, 56, 153, 4, 174, 102, 112, 28, 162, 64, 44, 60,
    213, 100, 2, 32, 49, 19, 136, 160, 56, 233, 56, 176, 40, 4, 227, 47, 135, 81,
    79, 233, 233, 93, 249, 146, 2, 116, 213, 39, 183, 242, 72, 188, 44, 66, 115,
    60>>
  @test_sig_b64 "MEQCICpBotZ5/8zM44nTsnqArOikdjU4mQSuZnAcokAsPNVkAiAxE4igOOk4sCgE4y+HUU/p6V35kgJ01Se38ki8LEJzPA=="
  @test_sig_hex "304402202a41a2d679ffcccce389d3b27a80ace8a47635389904ae66701ca2402c3cd5640220311388a038e938b02804e32f87514fe9e95df9920274d527b7f248bc2c42733c"

  @test_sig_c <<
    32, 42, 65, 162, 214, 121, 255, 204, 204, 227, 137, 211, 178, 122, 128, 172,
    232, 164, 118, 53, 56, 153, 4, 174, 102, 112, 28, 162, 64, 44, 60, 213, 100,
    49, 19, 136, 160, 56, 233, 56, 176, 40, 4, 227, 47, 135, 81, 79, 233, 233, 93,
    249, 146, 2, 116, 213, 39, 183, 242, 72, 188, 44, 66, 115, 60>>
  @test_sig_c_b64 "ICpBotZ5/8zM44nTsnqArOikdjU4mQSuZnAcokAsPNVkMROIoDjpOLAoBOMvh1FP6eld+ZICdNUnt/JIvCxCczw="
  @test_sig_c_hex "202a41a2d679ffcccce389d3b27a80ace8a47635389904ae66701ca2402c3cd564311388a038e938b02804e32f87514fe9e95df9920274d527b7f248bc2c42733c"

  describe "sign/3" do
    test "signs a message with the given encoding" do
      assert Curvy.sign("hello", @test_key) == @test_sig
      assert Curvy.sign("hello", @test_key, encoding: :base64) == @test_sig_b64
      assert Curvy.sign("hello", @test_key, encoding: :hex) == @test_sig_hex
    end

    test "signs a compact message with the given encoding" do
      assert Curvy.sign("hello", @test_key, compact: true) == @test_sig_c
      assert Curvy.sign("hello", @test_key, compact: true, encoding: :base64) == @test_sig_c_b64
      assert Curvy.sign("hello", @test_key, compact: true, encoding: :hex) == @test_sig_c_hex
    end

    test "returns signature with recovery id" do
      assert {sig, recovery_id} = Curvy.sign("hello", @test_key, recovery: true)
      assert sig == @test_sig
      assert is_integer(recovery_id)
    end

    test "signs a message without hash digest" do
      refute Curvy.sign("hello", @test_key, hash: false) == @test_sig
    end

    test "signs a message without low s normalization" do
      refute Curvy.sign("hello", @test_key, normalize: false) == @test_sig
    end

    test "verifyable with built in erlang crypto" do
      assert :crypto.verify(:ecdsa, :sha256, "hello", @test_sig, [Key.to_pubkey(@test_key), :secp256k1])
      assert :crypto.verify(:ecdsa, :sha256, "hello", Curvy.sign("hello", @test_key, normalize: false), [Key.to_pubkey(@test_key), :secp256k1])
    end
  end

  describe "verify/4" do
    test "verifies signatures with the given encoding" do
      assert Curvy.verify(@test_sig, "hello", @test_key)
      assert Curvy.verify(@test_sig_b64, "hello", @test_key, encoding: :base64)
      assert Curvy.verify(@test_sig_hex, "hello", @test_key, encoding: :hex)
    end

    test "verifies compact signatures with the given encoding" do
      assert Curvy.verify(@test_sig_c, "hello", @test_key)
      assert Curvy.verify(@test_sig_c_b64, "hello", @test_key, encoding: :base64)
      assert Curvy.verify(@test_sig_c_hex, "hello", @test_key, encoding: :hex)
    end

    test "verifies a message without hash digest" do
      Curvy.sign("hello", @test_key, hash: false)
      |> Curvy.verify("hello", @test_key, hash: false)
      |> assert
    end

    test "verifies a message without low s normalization" do
      Curvy.sign("hello", @test_key, normalize: false)
      |> Curvy.verify("hello", @test_key)
      |> assert
    end

    test "wont verify if message incorrect" do
      refute Curvy.verify(@test_sig, "wrong", @test_key)
    end

    test "wont verify if key incorrect" do
      refute Curvy.verify(@test_sig, "hello", @test_key_2)
    end

    test "wont verify if hash algo incorrect" do
      refute Curvy.verify(@test_sig, "hello", @test_key, hash: false)
    end

    test "returns error if signature is garbage" do
      assert :error = Curvy.verify(:crypto.strong_rand_bytes(32), "hello", @test_key)
    end

    test "returns error if signature decoding error" do
      assert :error = Curvy.verify(@test_sig_b64, "hello", @test_key, encoding: :hex)
    end
  end
end
