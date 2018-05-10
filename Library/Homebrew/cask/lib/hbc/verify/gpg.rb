require "formula"

module Hbc
  module Verify
    class Gpg
      def self.me?(cask)
        !cask.gpg.nil?
      end

      attr_reader :cask, :downloaded_path

      def initialize(cask, downloaded_path, command = SystemCommand)
        @command = command
        @cask = cask
        @downloaded_path = downloaded_path
      end

      def installed?
        Formula["gnupg"].any_version_installed?
      end

      def fetch_sig(_force = false)
        url = cask.gpg.signature

        signature_filename = "#{Digest::SHA2.hexdigest(url.to_s)}.asc"
        signature_file = Hbc.cache/signature_filename

        unless signature_file.exist?
          ohai "Fetching GPG signature '#{cask.gpg.signature}'."
          curl_download cask.gpg.signature, to: signature_file
        end

        FileUtils.ln_sf signature_filename, Hbc.cache/"#{cask.token}--#{cask.version}.asc"

        signature_file
      end

      def import_key
        args = if cask.gpg.key_id
          ["--receive-keys", cask.gpg.key_id]
        elsif cask.gpg.key_url
          ["--fetch-keys", cask.gpg.key_url.to_s]
        end

        gpg(args: args, print_stderr: false)
      end

      def verify
        unless installed?
          ohai "Formula 'gnupg' is not installed, skipping verification of GPG signature for Cask '#{cask}'."
          return
        end

        if cask.gpg.signature == :embedded
          ohai "Skipping verification of embedded GPG signature for Cask '#{cask}'."
          return
        end

        if cask.gpg.signature.is_a?(Pathname)
          ohai "Skipping verification of GPG signature included in container for Cask '#{cask}'."
          return
        end

        import_key
        sig = fetch_sig

        ohai "Verifying GPG signature for Cask '#{cask}'."

        gpg(args: ["--verify", sig, downloaded_path], print_stderr: false)
      end

      def gpg(args: [], **options)
        (HOMEBREW_CACHE/"gpg").mkpath
        @command.run!(Formula["gnupg"].opt_bin/"gpg", args: ["--no-default-keyring", "--keyring", HOMEBREW_CACHE/"gpg/homebrew-keyring.gpg", *args], **options)
      end
    end
  end
end
