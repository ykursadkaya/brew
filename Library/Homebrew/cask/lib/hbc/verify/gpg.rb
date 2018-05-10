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

        homebrew_keyring_path = (HOMEBREW_CACHE/"gpg/homebrew-keyring.gpg").tap do |path|
          path.dirname.mkpath
        end

        homebrew_keyring_args = ["--no-default-keyring", "--keyring", homebrew_keyring_path]

        # Ensure GPG installation is initialized.
        gpg(args: ["--list-keys"], print_stderr: false)

        if cask.gpg.key_id
          gpg(args: [*homebrew_keyring_args, "--receive-keys", cask.gpg.key_id], print_stderr: false)
        elsif cask.gpg.key_url
          gpg(args: [*homebrew_keyring_args, "--fetch-keys", cask.gpg.key_url.to_s], print_stderr: false)
        end

        sig = fetch_sig

        ohai "Verifying GPG signature for Cask '#{cask}'."

        gpg(args: [*homebrew_keyring_args, "--verify", sig, downloaded_path], print_stderr: false)
      end

      def gpg(args: [], **options)
        @command.run!(Formula["gnupg"].opt_bin/"gpg", args: args, **options)
      end
    end
  end
end
