control 'SV-234834' do
  title 'The SUSE operating system library files must have mode 0755 or less permissive.'
  desc 'If the SUSE operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to SUSE operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', %q(Verify the systemwide shared library files contained in the directories "/lib", "/lib64", "/usr/lib", and "/usr/lib64" have mode 0755 or less permissive.

Check that the systemwide shared library files have mode 0755 or less permissive with the following command:

> sudo find /lib /lib64 /usr/lib /usr/lib64 -type f -name '*.so*' -perm /022 -exec stat -c "%n %a" {} +

If any output is returned, this is a finding.)
  desc 'fix', %q(Configure the systemwide shared library files contained in the directories "/lib", "/lib64", "/usr/lib", and "/usr/lib64" to have mode 0755 or less permissive with the following command:

> sudo find /lib /lib64 /usr/lib /usr/lib64 -type f -name '*.so*' -perm /022 -exec chmod go-w {} +)
  impact 0.5
  tag check_id: 'C-38022r1106557_chk'
  tag severity: 'medium'
  tag gid: 'V-234834'
  tag rid: 'SV-234834r1106567_rule'
  tag stig_id: 'SLES-15-010351'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-37985r1106566_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
