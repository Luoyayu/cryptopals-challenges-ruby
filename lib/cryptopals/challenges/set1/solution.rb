# frozen_string_literal: true

require "cryptopals/utils"

module Cryptopals
  module Challenges
    module Set1
      # Convert hex to base64
      module Solution1
        def self.solve(hex_string)
          require "base64"
          # Base64.strict_encode64 hex_string.unhexed # hook class `String`
          unhexed = ->(str) { str.scan(/../).map { |x| x.hex.chr }.join }
          Base64.strict_encode64 unhexed[hex_string]
        end
      end

      # Fixed XOR
      module Solution2
        def self.solve(hex_string1, hex_string2)
          block_size = 32
          xor_hex_block = ->(b1, b2) { (b1.hex ^ b2.hex).to_s 16 }
          0.step(by: block_size, to: hex_string1.size).map do |i|
            xor_hex_block[hex_string1[i, block_size], hex_string2[i, block_size]]
          end.join
        end
      end

      # Single-byte XOR cipher
      module Solution3
        def self.evaluate(string) = string.scan(/[ETAOIN SHRDLU]/i).size > string.size * 0.6

        def self.solve(hex_string)
          (0..255).each do |key|
            try_decrypted = hex_string.scan(/../).map { |h| (h.hex ^ key).chr }.join
            return try_decrypted if evaluate(try_decrypted)
          end
          nil # useful for Solution4
        end
      end

      # Detect single-character XOR
      module Solution4
        def self.solve(file_path)
          File.open file_path do |file|
            file.each_line do |line|
              try_decrypted = Solution3.solve(line.chomp)
              return try_decrypted.chomp if try_decrypted
            end
          end
        end
      end

      # Implement repeating-key XOR
      module Solution5
        def self.solve(data, key)
          key = key.each_byte.to_a
          data.each_byte.each_slice(key.size).map do |block|
            block.each_with_index.map { |v, i| "%02x" % (v ^ key[i]) }
          end.join
        end
      end

      # Break repeating-key XOR
      module Solution6
        def self.solve(file_path)
          require "base64"
          file = Base64.decode64 File.read(file_path)
          key, key_size = [], guess_key_size(file)
          # puts "guessed KEYSIZE is #{key_size}"

          # break the ciphertext into blocks of KEYSIZE length.
          blocks = file.split(//).each_slice(key_size).map { |slice| slice }
          blocks.delete_at(-1) if blocks[-1].size != key_size # drop the last block
          # puts "break the ciphertext into #{blocks.size} blocks"

          # transpose the blocks
          transposed_blocks = blocks.transpose

          evaluate = ->(string) { string.scan(/[ETAOIN SHRDLU]/i).size > string.size * 0.6 }

          transposed_blocks.each do |block|
            (0..255).each do |single_key|
              try_decrypted = block.map { |e| (e.ord ^ single_key).chr }.join
              if evaluate[try_decrypted]
                key << single_key.chr
                break
              end
            end
          end

          key.join
        end

        def self.guess_key_size(string)
          key_size = 2
          hamming = string.length * 8
          (key_size..40).each do |size|
            n = 8
            x = string[0...size * n]
            y = string[size * n...size * n * 2]
            hamming_xy = hamming_distance(x, y).to_f / n / size
            if hamming_xy < hamming
              key_size = size
              hamming = hamming_xy
            end
          end
          key_size
        end

        def self.hamming_distance(str1, str2)
          str2bin = ->(str) { str.each_byte.map { |int| "%08b" % int }.join }
          str1, str2 = str2bin[str1], str2bin[str2]
          str1.length.times.map { |i| str1[i] != str2[i] }.count true
        end
      end

      # AES in ECB mode
      module Solution7
        def self.solve(file_path)
          require "base64"
          require "openssl"

          file = Base64.decode64 File.read(file_path)
          secret_key = "YELLOW SUBMARINE"

          cipher = OpenSSL::Cipher.new("AES-128-ECB").decrypt
          cipher.key = secret_key
          cipher.update(file) << cipher.final
        end
      end

      # Detect AES in ECB mode
      module Solution8
        def self.solve(file_path)
          file = (File.readlines file_path, chomp: true).join
          blocks = Hash.new { 0 }
          (0..file.size).step(32) { |i| blocks[file[i, 32]] += 1 }
          blocks.select { |_, v| v >= 2 }
        end
      end

    end
  end
end
