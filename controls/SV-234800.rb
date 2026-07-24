control 'SV-234800' do
  title 'The SUSE operating system must be a vendor-supported release.'
  desc 'A SUSE operating system release is considered "supported" if the vendor continues to provide security patches for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the system software.

Release		Released		General Support		Long Term Support
15.1		24 Jun 2019		31 Jan 2021			31 Jan 2024
15.2		21 Jul 2020		31 Dec 2021			31 Dec 2024
15.3		22 Jun 2021		31 Dec 2022			31 Dec 2025
15.4		21 Jun 2022		31 Dec 2023			31 Dec 2026
15.5		20 Jun 2023		31 Dec 2024			31 Dec 2027
15.6		26 Jun 2024		31 Dec 2025			31 Dec 2028
15.7		17 Jun 2025		31 Jul 2031			31 Jul 2034'
  desc 'check', 'Verify the SUSE operating system is a vendor-supported release.

Use the following command to verify the SUSE operating system is a vendor-supported release:

> cat /etc/os-release

NAME="SLES"
VERSION="15"

Or any SUSE Linux Enterprise 15 Service Pack follow up release.

NAME="SLES"
VERSION="15-SPx"

Current End of Life for SLES 15 General Support is 31 Jul 2028 and Long-term Support is until 31 Jul 2031.

If the release is not supported by the vendor, this is a finding.'
  desc 'fix', 'Upgrade the SUSE operating system to a version supported by the vendor. If the system is not registered with the SUSE Customer Center, register the system against the correct subscription.

If the system requires Long-Term Service Pack Support (LTSS), obtain the correct LTSS subscription for the system.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-234800'
  tag rid: 'SV-234800r1155796_rule'
  tag stig_id: 'SLES-15-010000'
  tag fix_id: 'F-37951r618670_fix'
  tag cci: ['CCI-000366', 'CCI-001230']
  tag nist: ['CM-6 b', 'SI-2 d']
  tag 'host'
  tag 'container'

  release = os.release

  # Match both the VM dotted form (15.6) and the BCI container form (15-SP6).
  EOMS_DATE = {
    /^15[.-](SP)?1\b/ => 'January 31, 2024',
    /^15[.-](SP)?2\b/ => 'December 31, 2024',
    /^15[.-](SP)?3\b/ => 'December 31, 2025',
    /^15[.-](SP)?4\b/ => 'December 31, 2026',
    /^15[.-](SP)?5\b/ => 'December 31, 2027',
    /^15[.-](SP)?6\b/ => 'December 31, 2028',
    /^15[.-](SP)?7\b/ => 'July 31, 2034'
  }.find { |k, _v| k.match(release) }&.last

  describe "The release \"#{release}\"" do
    if EOMS_DATE.nil?
      it 'is a supported release' do
        expect(EOMS_DATE).not_to be_nil, "Release '#{release}' has no specified support window"
      end
    else
      it 'is still within the support window' do
        expect(Date.today).to be <= Date.parse(EOMS_DATE)
      end
    end
  end
end
