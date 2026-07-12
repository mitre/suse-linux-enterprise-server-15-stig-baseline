control 'SV-234885' do
  title 'The SUSE operating system must require the change of at least eight of the total number of characters when passwords are changed.'
  desc 'If the SUSE operating system allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.'
  desc 'check', 'Verify the SUSE operating system requires at least eight characters be changed between the old and new passwords during a password change.

Check that the operating system requires at least eight characters be changed between the old and new passwords during a password change by running the following command:

> grep pam_cracklib.so /etc/pam.d/common-password
password requisite pam_cracklib.so difok=8

If the command does not return anything, the returned line is commented out, or has a second column value different from "requisite", or does not contain "difok", or the value is less than "8", this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to require at least eight characters be changed between the old and new passwords during a password change with the following command:

Edit "/etc/pam.d/common-password" and edit the line containing "pam_cracklib.so" to contain the option "difok=8" after the third column.'
  impact 0.5
  tag check_id: 'C-38073r618924_chk'
  tag severity: 'medium'
  tag gid: 'V-234885'
  tag rid: 'SV-234885r1009624_rule'
  tag stig_id: 'SLES-15-020160'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag fix_id: 'F-38036r618925_fix'
  tag 'documentable'
  tag cci: ['CCI-000195', 'CCI-004066']
  tag nist: ['IA-5 (1) (b)', 'IA-5 (1) (h)']
  tag 'host'
  tag 'container'

  expected_value = input('difok')
  cracklib_line = file('/etc/pam.d/common-password').content.to_s.lines.map(&:strip).reject { |l| l.start_with?('#') }.find { |l| l.include?('pam_cracklib.so') }

  describe 'The pam_cracklib.so line in /etc/pam.d/common-password' do
    it 'should be present and not commented out' do
      expect(cracklib_line).not_to be_nil, 'No pam_cracklib.so line found in /etc/pam.d/common-password'
    end
    it 'should have `requisite` as the second column' do
      expect(cracklib_line.to_s.split[1]).to eq('requisite'), "Second column is '#{cracklib_line.to_s.split[1]}', expected 'requisite'"
    end
    it "should set difok to #{expected_value} or greater" do
      value = cracklib_line.to_s[/\bdifok=(\d+)/, 1]
      expect(value).not_to be_nil, 'pam_cracklib.so line does not contain difok'
      expect(value.to_i).to be >= expected_value, "difok is set to '#{value}', expected >= #{expected_value}"
    end
  end
end
