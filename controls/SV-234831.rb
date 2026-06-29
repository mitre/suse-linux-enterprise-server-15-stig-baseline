control 'SV-234831' do
  title 'All SUSE operating system persistent disk partitions must implement cryptographic mechanisms to prevent unauthorized disclosure or modification of all information that requires at-rest protection.'
  desc 'SUSE operating systems handling data requiring data-at-rest protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields).'
  desc 'check', 'Verify the SUSE operating system prevents unauthorized disclosure or modification of all information requiring at rest protection by using disk encryption.

Determine the partition layout for the system with the following command:

> sudo fdisk -l

Device Boot Start End Sectors Size Id Type
/dev/sda1 2048 4208639 4206592 2G 82 Linux swap
/dev/sda2 * 4208640 53479423 49270784 23.5G 83 Linux
/dev/sda3 53479424 125829119 72349696 34.5G 83 Linux

Verify the system partitions are all encrypted with the following command:

> sudo more /etc/crypttab

cr_root  UUID=26d4a101-7f48-4394-b730-56dc00e65f64
cr_home  UUID=f5b8a790-14cb-4b82-882d-707d52f27765
cr_swap  UUID=f2d86128-f975-478d-a5b0-25806c900eac


Every persistent disk partition present on the system must have an entry in the file.

If any partitions other than pseudo file systems (such as /proc or /sys) are not listed or "/etc/crypttab" does not exist, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to prevent unauthorized modification of all information at rest by using disk encryption.

Encrypting a partition in an already-installed system is more difficult because of the need to resize and change existing partitions. To encrypt an entire partition, dedicate a partition for encryption in the partition layout. The standard partitioning proposal as suggested by YaST (installation and configuration tool for Linux) does not include an encrypted partition by default. Add it manually in the partitioning dialog.

Refer to the document "SUSE Linux Enterprise Server 15 SP1 - Security Guide", Section 12.1.2, for a detailed disk encryption guide:

https://documentation.suse.com/sles/15-SP1/html/SLES-all/cha-security-cryptofs.html#sec-security-cryptofs-y2-part-run'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000185-GPOS-00079'
  tag satisfies: ['SRG-OS-000185-GPOS-00079', 'SRG-OS-000404-GPOS-00183', 'SRG-OS-000405-GPOS-00184']
  tag gid: 'V-234831'
  tag rid: 'SV-234831r1009558_rule'
  tag stig_id: 'SLES-15-010330'
  tag fix_id: 'F-37982r618763_fix'
  tag cci: ['CCI-001199', 'CCI-002475', 'CCI-002476']
  tag nist: ['SC-28', 'SC-28 (1)']
  tag 'host'

  all_args = command('blkid').stdout.strip.split("\n").map { |s| s.sub(/^"(.*)"$/, '\1') }

  def describe_and_skip(message)
    describe message do
      skip message
    end
  end

  # TODO: This should really have a resource

  if %w[docker podman kubepods lxc].include?(virtualization.system)
    impact 0.0
    describe_and_skip('Disk Encryption and Data At Rest Implementation is handled on the Container Host')
  elsif input('data_at_rest_exempt')
    impact 0.0
    describe_and_skip('Data At Rest Requirements have been set to Not Applicable by the `data_at_rest_exempt` input.')
  elsif all_args.empty?
    # TODO: Determine if this is an NA vs and NR or even a pass
    describe_and_skip('Command blkid did not return and non-psuedo block devices.')
  else
    unencrypted_drives = all_args.reject { |a|
      a.match(/\bcrypto_LUKS\b/) ||
        input('luks_exceptions').include?(a.split(':').first) ||
        a.split(':').first.match(%r{^/dev/mapper/})
    }
    describe 'All local disk partitions' do
      it 'should be encrypted with crypto_LUKS' do
        expect(unencrypted_drives).to be_empty, "The following partitions are not encrypted with crypto_LUKS:\t\n- #{unencrypted_drives.join("\t\n- ")}"
      end
    end
  end
end
