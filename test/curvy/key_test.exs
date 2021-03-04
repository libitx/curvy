defmodule Curvy.KeyTest do
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

  @test_pubkey <<
    4, 9, 27, 16, 2, 243, 64, 193, 241, 146, 134, 164, 106, 209, 196, 98, 108,
    104, 106, 24, 91, 35, 36, 119, 126, 92, 179, 246, 227, 179, 30, 51, 183, 147,
    171, 252, 131, 45, 2, 229, 218, 144, 188, 13, 47, 211, 169, 39, 200, 106, 93,
    98, 149, 189, 109, 177, 223, 63, 124, 193, 247, 77, 138, 127, 129>>
  @test_pubkey_comp <<
    3, 9, 27, 16, 2, 243, 64, 193, 241, 146, 134, 164, 106, 209, 196, 98, 108,
    104, 106, 24, 91, 35, 36, 119, 126, 92, 179, 246, 227, 179, 30, 51, 183>>


  describe "generate/0" do
    test "returns a randomly generated key" do
      assert %Key{crv: :secp256k1, point: p, privkey: privkey} = Key.generate()
      assert is_integer(p.x)
      assert is_integer(p.y)
      assert is_binary(privkey)
    end
  end


  describe "from_privkey/1" do
    test "converts valid privkey into a key pair" do
      assert %Key{crv: :secp256k1, point: p} = Key.from_privkey(@test_key.privkey)
      assert p.x == @test_key.point.x
      assert p.y == @test_key.point.y
    end
  end


  describe "from_pubkey/2" do
    test "parses valid pubkey binary" do
      assert %Key{crv: :secp256k1, point: p} = Key.from_pubkey(@test_pubkey)
      assert p.x == @test_key.point.x
      assert p.y == @test_key.point.y
    end

    test "parses valid compressed pubkey binary" do
      assert %Key{crv: :secp256k1, point: p} = Key.from_pubkey(@test_pubkey_comp)
      assert p.x == @test_key.point.x
      assert p.y == @test_key.point.y
    end
  end


  describe "to_privkey/1" do
    test "returns privkey binary" do
      assert <<_privkey::binary-size(32)>> = Key.to_privkey(@test_key)
    end
  end


  describe "to_pubkey/2" do
    test "returns pubkey binary with given encoding and compression" do
      assert <<_pubkey::binary-size(33)>> = Key.to_pubkey(@test_key)
      assert <<_pubkey::binary-size(65)>> = Key.to_pubkey(@test_key, compressed: false)
    end
  end

end
