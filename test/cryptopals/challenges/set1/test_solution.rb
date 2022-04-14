$LOAD_PATH.unshift File.expand_path("../../../../lib", __dir__)
require "test_helper"

class CryptopalsTestSet1 < Minitest::Test
  require "cryptopals/challenges/set1/solution"

  def test_set1_solution1
    hexed = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    act = Cryptopals::Challenges::Set1::Solution1.solve hexed
    wanted = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    assert_operator act, :==, wanted
  end

  def test_set1_solution2
    hex_string1 = "1c0111001f010100061a024b53535009181c"
    hex_string2 = "686974207468652062756c6c277320657965"
    act = Cryptopals::Challenges::Set1::Solution2.solve hex_string1, hex_string2
    wanted = "746865206b696420646f6e277420706c6179"
    assert_operator act, :==, wanted
  end

  def test_set1_solution3
    hex_string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    act = Cryptopals::Challenges::Set1::Solution3.solve hex_string
    wanted = "Cooking MC's like a pound of bacon"
    assert_operator act, :==, wanted
  end

  def test_set1_solution4
    test_file = "test/cryptopals/challenges/set1/challenge-data-4.txt"
    act = Cryptopals::Challenges::Set1::Solution4.solve test_file
    wanted = "Now that the party is jumping"
    assert_operator act, :==, wanted
  end

  def test_set1_solution5
    data = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"
    key = "ICE"
    wanted = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272" \
             "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    act = Cryptopals::Challenges::Set1::Solution5.solve data, key
    assert_operator act, :==, wanted
  end

  def test_set1_solution6_hamming_distance
    str1 = "this is a test"
    str2 = "wokka wokka!!!"
    wanted = 37
    act = Cryptopals::Challenges::Set1::Solution6.hamming_distance str1, str2
    assert_operator act, :==, wanted
  end

  def test_set1_solution6
    test_file = "test/cryptopals/challenges/set1/challenge-data-6.txt"
    act = Cryptopals::Challenges::Set1::Solution6.solve test_file
    wanted = "TermiNator X: Bring the noise"
    assert_operator act, :==, wanted
  end

  def test_set1_solution7
    require "openssl"
    require "base64"
    test_file = "test/cryptopals/challenges/set1/challenge-data-7.txt"
    act = Cryptopals::Challenges::Set1::Solution7.solve test_file

    digest = OpenSSL::Digest.new("SHA256").update(act)
    act = Base64.strict_encode64 digest.digest
    wanted = "JN+EUz/Cd4SVV3yES88/4dTRfGjYxcvFowgobbWMabY="
    assert_operator act, :==, wanted
  end

  def test_set1_solution8
    test_file = "test/cryptopals/challenges/set1/challenge-data-8.txt"
    act = Cryptopals::Challenges::Set1::Solution8.solve test_file
    wanted = { "08649af70dc06f4fd5d2d69c744cd283" => 4 }
    assert_operator act, :==, wanted
  end

end
