control 'SV-234843' do
  title 'The SUSE operating system must have directories that contain system commands owned by root.'
  desc 'If the SUSE operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to SUSE operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', %q(Verify the system commands directories are owned by root:

/bin
/sbin
/usr/bin
/usr/sbin
/usr/local/bin
/usr/local/sbin

Use the following command for the check:

> sudo find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec stat -c "%n %U" '{}' \;

If any system commands directories are returned, this is a finding.)
  desc 'fix', "Configure the system commands directories to be protected from unauthorized access. Run the following command:

> sudo find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec chown root '{}' \\;"
  impact 0.5
  tag check_id: 'C-38031r618798_chk'
  tag severity: 'medium'
  tag gid: 'V-234843'
  tag rid: 'SV-234843r991560_rule'
  tag stig_id: 'SLES-15-010360'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-37994r618799_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  dirs = input('system_command_dirs').select { |d| file(d).exist? }

  find_cmd = "find -L #{dirs.join(' ')} ! -user root -type d -exec stat -c '%n %U' '{}' \\;"
  non_root_owned_dirs = command(find_cmd).stdout.strip.split("\n").reject(&:empty?)

  describe 'System command directories not owned by root' do
    it 'should have every system command directory owned by root' do
      expect(non_root_owned_dirs).to be_empty, "Directories not owned by root (run: chown root <dir>):\n\t- #{non_root_owned_dirs.join("\n\t- ")}"
    end
  end
end
