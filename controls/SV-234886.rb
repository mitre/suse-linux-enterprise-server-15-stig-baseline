control 'SV-234886' do
  title 'The SUSE operating system must configure the Linux Pluggable Authentication Modules (PAM) to only store encrypted representations of passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.'
  desc 'check', 'Verify the SUSE operating system configures the Linux PAM to only store encrypted representations of passwords. All account passwords must be hashed with SHA512 encryption strength.

Check that PAM is configured to create SHA512 hashed passwords by running the following command:

> grep pam_unix.so /etc/pam.d/common-password
password required pam_unix.so sha512

If the command does not return anything or the returned line is commented out, has a second column value different from "required", or does not contain "sha512", this is a finding.'
  desc 'fix', 'Configure the SUSE operating system Linux PAM to only store encrypted representations of passwords. All account passwords must be hashed with SHA512 encryption strength.

Edit "/etc/pam.d/common-password" and edit the line containing "pam_unix.so" to contain the SHA512 keyword after third column. Remove the "nullok" option.'
  impact 0.5
  tag check_id: 'C-38074r618927_chk'
  tag severity: 'medium'
  tag gid: 'V-234886'
  tag rid: 'SV-234886r1009625_rule'
  tag stig_id: 'SLES-15-020170'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-38037r618928_fix'
  tag 'documentable'
  tag cci: ['CCI-000196', 'CCI-004062']
  tag nist: ['IA-5 (1) (c)', 'IA-5 (1) (d)']
  tag 'host'
  tag 'container'

  pam_unix_line = file('/etc/pam.d/common-password').content.to_s.lines.map(&:strip).reject { |l| l.start_with?('#') }.find { |l| l.include?('pam_unix.so') }

  describe 'The pam_unix.so line in /etc/pam.d/common-password' do
    it 'should be present and not commented out' do
      expect(pam_unix_line).not_to be_nil, 'No pam_unix.so line found in /etc/pam.d/common-password'
    end
    it 'should have `required` as the second column' do
      expect(pam_unix_line.to_s.split[1]).to eq('required'), "Second column is '#{pam_unix_line.to_s.split[1]}', expected 'required'"
    end
    it 'should contain sha512' do
      expect(pam_unix_line).to match(/\bsha512\b/), 'pam_unix.so line does not contain sha512'
    end
  end
end
