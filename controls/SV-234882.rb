control 'SV-234882' do
  title 'The SUSE operating system must enforce passwords that contain at least one uppercase character.'
  desc 'Use of a complex password helps increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Verify the SUSE operating system enforces password complexity by requiring at least one uppercase character.

Check that the operating system enforces password complexity by requiring that at least one uppercase character be used by using the following command:

> grep pam_cracklib.so /etc/pam.d/common-password
password requisite pam_cracklib.so ucredit=-1

If the command does not return anything, the returned line is commented out, or has a second column value different from "requisite", or does not contain "ucredit=-1", this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to enforce password complexity by requiring at least one uppercase character.

Edit "/etc/pam.d/common-password" and edit the line containing "pam_cracklib.so" to contain the option "ucredit=-1" after the third column.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag gid: 'V-234882'
  tag rid: 'SV-234882r1009621_rule'
  tag stig_id: 'SLES-15-020130'
  tag fix_id: 'F-38033r618916_fix'
  tag cci: ['CCI-000192', 'CCI-004066']
  tag nist: ['IA-5 (1) (a)', 'IA-5 (1) (h)']
  tag 'host'
  tag 'container'

  cracklib_line = file('/etc/pam.d/common-password').content.to_s.lines.map(&:strip).reject { |l| l.start_with?('#') }.find { |l| l.include?('pam_cracklib.so') }

  describe 'The pam_cracklib.so line in /etc/pam.d/common-password' do
    it 'should be present and not commented out' do
      expect(cracklib_line).not_to be_nil, 'No pam_cracklib.so line found in /etc/pam.d/common-password'
    end
    it 'should have `requisite` as the second column' do
      expect(cracklib_line.to_s.split[1]).to eq('requisite'), "Second column is '#{cracklib_line.to_s.split[1]}', expected 'requisite'"
    end
    it 'should contain ucredit=-1' do
      expect(cracklib_line).to match(/\bucredit=-1\b/), 'pam_cracklib.so line does not contain ucredit=-1'
    end
  end
end
