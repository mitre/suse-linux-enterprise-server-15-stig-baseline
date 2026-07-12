control 'SV-234841' do
  title 'The SUSE operating system must have directories that contain system commands set to a mode of 0755 or less permissive.'
  desc 'If the SUSE operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to SUSE operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', %q(Verify the system commands directories have mode "0755" or less permissive:

/bin
/sbin
/usr/bin
/usr/sbin
/usr/local/bin
/usr/local/sbin

Check that the system command directories have mode "0755" or less permissive with the following command:

> find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec stat -c "%n %a" '{}' \;

If any directories are found to be group-writable or world-writable, this is a finding.)
  desc 'fix', "Configure the system commands directories to be protected from unauthorized access. Run the following command:

> sudo find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec chmod -R 755 '{}' \\;"
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag gid: 'V-234841'
  tag rid: 'SV-234841r991560_rule'
  tag stig_id: 'SLES-15-010358'
  tag fix_id: 'F-37992r618793_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
  tag 'host'
  tag 'container'

  failing_dirs = command("find -L #{input('system_command_dirs').join(' ')} -perm /022 -type d").stdout.strip

  describe 'System command directories more permissive than 0755' do
    it 'should not exist' do
      expect(failing_dirs).to be_empty, "Group- or world-writable directories:\n\t- #{failing_dirs.split("\n").join("\n\t- ")}"
    end
  end
end
