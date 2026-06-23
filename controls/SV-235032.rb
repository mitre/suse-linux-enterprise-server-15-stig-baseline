control 'SV-235032' do
  title 'The SUSE operating system must not allow unattended or automatic logon via SSH.'
  desc 'Failure to restrict system access via SSH to authenticated users negatively impacts SUSE operating system security.'
  desc 'check', %q(Verify the SUSE operating system disables unattended or automatic logon via SSH.

Check that unattended or automatic logon via SSH is disabled with the following command:

> sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iEH '^\s*(permit(.*?)(passwords|environment))'

PermitEmptyPasswords no
PermitUserEnvironment no

If "PermitEmptyPasswords" or "PermitUserEnvironment" keywords are not set to "no", are missing completely, or are commented out, this is a finding.)
  desc 'fix', 'Configure the SUSE operating system disables unattended or automatic logon via SSH.

Add or edit the following lines in the "/etc/ssh/sshd_config" file:

PermitEmptyPasswords no
PermitUserEnvironment no'
  impact 0.7
  tag check_id: 'C-38220r951647_chk'
  tag severity: 'high'
  tag gid: 'V-235032'
  tag rid: 'SV-235032r991591_rule'
  tag stig_id: 'SLES-15-040440'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-38183r619366_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
