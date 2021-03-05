defmodule Curvy.SignatureTest do
  use ExUnit.Case, async: true
  alias Curvy.Signature

  @test_sig %Signature{
    r: 63173831029936981022572627018246571655303050627048489594159321588908385378810,
    s: 4331694221846364448463828256391194279133231453999942381442030409253074198130,
    recid: 0
  }

  @test_der <<
    48, 69, 2, 33, 0, 139, 171, 31, 10, 47, 242, 249, 203, 137, 146, 23, 61, 138,
    215, 60, 34, 157, 49, 234, 142, 16, 176, 244, 212, 174, 26, 13, 142, 215, 96,
    33, 250, 2, 32, 9, 147, 166, 236, 129, 117, 91, 145, 17, 118, 47, 194, 207,
    142, 62, 222, 115, 4, 117, 21, 98, 39, 146, 17, 8, 103, 209, 38, 84, 39, 94,
    114>>

  @test_compact <<
    31, 139, 171, 31, 10, 47, 242, 249, 203, 137, 146, 23, 61, 138, 215, 60, 34,
    157, 49, 234, 142, 16, 176, 244, 212, 174, 26, 13, 142, 215, 96, 33, 250, 9,
    147, 166, 236, 129, 117, 91, 145, 17, 118, 47, 194, 207, 142, 62, 222, 115, 4,
    117, 21, 98, 39, 146, 17, 8, 103, 209, 38, 84, 39, 94, 114
  >>


  describe "parse/2" do
    test "parses a valid der signature" do
      assert %Signature{r: r, s: s, recid: recid} = Signature.parse(@test_der)
      assert r == @test_sig.r
      assert s == @test_sig.s
      assert is_nil(recid)
    end

    test "parses a valid compact signature" do
      assert %Signature{r: r, s: s, recid: recid} = Signature.parse(@test_compact)
      assert r == @test_sig.r
      assert s == @test_sig.s
      assert recid == 0
    end
  end


  describe "to_der/1" do
    test "returns der encoded signature" do
      assert Signature.to_der(@test_sig) == @test_der
    end
  end


  describe "to_compact/1" do
    test "returns compact signature" do
      assert Signature.to_compact(@test_sig) == @test_compact
    end

    test "returns compact signature with correct prefix" do
      assert <<32, _::binary>> = Signature.to_compact(@test_sig, recovery_id: 1)
      assert <<33, _::binary>> = Signature.to_compact(@test_sig, recovery_id: 2)
      assert <<34, _::binary>> = Signature.to_compact(@test_sig, recovery_id: 3)
    end

    test "returns compact signature with correct prefix for uncompressed" do
      assert <<28, _::binary>> = Signature.to_compact(@test_sig, recovery_id: 1, compressed: false)
      assert <<29, _::binary>> = Signature.to_compact(@test_sig, recovery_id: 2, compressed: false)
      assert <<30, _::binary>> = Signature.to_compact(@test_sig, recovery_id: 3, compressed: false)
    end

    test "raises error if not a valid recovery ID" do
      assert_raise RuntimeError, "Recovery ID not in range 0..3", fn -> @test_sig |> Map.put(:recid, nil) |> Signature.to_compact() end
      assert_raise RuntimeError, "Recovery ID not in range 0..3", fn -> Signature.to_compact(@test_sig, recovery_id: -1) end
      assert_raise RuntimeError, "Recovery ID not in range 0..3", fn -> Signature.to_compact(@test_sig, recovery_id: 4) end
    end
  end

end
