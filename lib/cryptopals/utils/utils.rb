# frozen_string_literal: true

module Cryptopals
  # Utils for Crypto
  module Utils
    def self.hello_crypto
      puts "Hello Crypto!"
    end
  end
end

class String
  def hexed = scan(/./).map { |int| "%02x" % int.ord }.join

  def unhexed = scan(/../).map { |x| x.hex.chr }.join
end
