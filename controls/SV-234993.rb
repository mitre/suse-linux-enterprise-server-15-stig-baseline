control 'SV-234993' do
  title 'All SUSE operating system local interactive user home directories must have mode 0750 or less permissive.'
  desc 'Excessive permissions on local interactive user home directories may
allow unauthorized access to user files by other users.'
  desc 'check', %q(Verify the assigned home directory of all SUSE operating system local interactive users has a mode of "0750" or less permissive.

Check the home directory assignment for all nonprivileged users on the system with the following command:

Note: This may miss interactive users that have been assigned a privileged User Identifier (UID). Evidence of interactive use may be obtained from a number of log files containing system logon information.

> ls -ld $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd)
-rwxr-x--- 1 doduser users 18 Mar 5 17:06 /home/doduser

If home directories referenced in "/etc/passwd" do not have a mode of "0750" or less permissive, this is a finding.)
  desc 'fix', %q(Change the mode of SUSE operating system local interactive user's home directories to "0750". To change the mode of a local interactive user's home directory, use the following command:

Note: The example will be for the user "doduser".

> sudo chmod 0750 /home/doduser)
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-234993'
  tag rid: 'SV-234993r1184474_rule'
  tag stig_id: 'SLES-15-040090'
  tag fix_id: 'F-38144r1184473_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  exempt_home_users = input('exempt_home_users')
  expected_mode = input('file_modes')['max'][:home_dirs]
  uid_min = login_defs.read_params['UID_MIN'].to_i
  uid_min = 1000 if uid_min.nil?

  iuser_entries = passwd.where { uid.to_i >= uid_min && shell !~ /nologin/ && !exempt_home_users.include?(user) }

  if !iuser_entries.users.nil? && !iuser_entries.users.empty?
    failing_homedirs = iuser_entries.homes.select { |home|
      file(home).more_permissive_than?(expected_mode)
    }
    describe 'All non-exempt interactive user account home directories on the system' do
      it "should not be more permissive than '#{expected_mode}'" do
        expect(failing_homedirs).to be_empty, "Failing home directories:\n\t- #{failing_homedirs.join("\n\t- ")}"
      end
    end
  else
    describe 'No non-exempt interactive user accounts' do
      it 'were detected on the system' do
        expect(true).to eq(true)
      end
    end
  end
end
