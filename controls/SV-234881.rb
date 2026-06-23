control 'SV-234881' do
  title 'The SUSE operating system must display the date and time of the last successful account logon upon an SSH logon.'
  desc 'Providing users with feedback on when account accesses via SSH last occurred facilitates user recognition and reporting of unauthorized account use.'
  desc 'check', %q(Verify all remote connections via SSH to the SUSE operating system display feedback on when account accesses last occurred.

Check that "PrintLastLog" keyword in the sshd daemon configuration file is used and set to "yes" with the following command:

> sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*printlastlog'

PrintLastLog yes

If the "PrintLastLog" keyword is set to "no", is missing, or is commented out, this is a finding.)
  desc 'fix', 'Configure the SUSE operating system to provide users with feedback on when account accesses last occurred.

Add or edit the following lines in the "/etc/ssh/sshd_config" file:

PrintLastLog yes'
  impact 0.5
  tag check_id: 'C-38069r951639_chk'
  tag severity: 'medium'
  tag gid: 'V-234881'
  tag rid: 'SV-234881r991589_rule'
  tag stig_id: 'SLES-15-020120'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-38032r618913_fix'
  tag 'documentable'
  tag cci: ['CCI-000052']
  tag nist: ['AC-9']
end
