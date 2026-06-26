control 'SV-234992' do
  title 'All SUSE operating system local interactive user home directories defined in the /etc/passwd file must exist.'
  desc 'If a local interactive user has a home directory defined that does not exist, the user may be given access to the / directory as the current working directory upon logon. This could create a Denial of Service because the user would not be able to access their logon configuration files, and it may give them visibility to system files they normally would not be able to access.'
  desc 'check', %q(Verify the assigned home directory of all SUSE operating system local interactive users on the system exists.

Check the home directory assignment for all local interactive nonprivileged users on the system with the following command:

> awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $6}' /etc/passwd

doduser /home/doduser

Note: This may miss interactive users that have been assigned a privileged User Identifier (UID). Evidence of interactive use may be obtained from a number of log files containing system logon information.

Check that all referenced home directories exist with the following command:

> sudo pwck -r

user 'doduser': directory '/home/doduser' does not exist

If any home directories referenced in "/etc/passwd" are returned as not defined, this is a finding.)
  desc 'fix', 'Create home directories to all SUSE operating system local interactive users that currently do not have a home directory assigned. Use the following commands to create the user home directory assigned in "/etc/ passwd":

Note: The example will be for the user doduser, who has a home directory of "/home/doduser", a UID of "doduser", and a Group Identifier (GID) of "users assigned" in "/etc/passwd".

> sudo mkdir /home/doduser 
> sudo chown doduser /home/doduser
> sudo chgrp users /home/doduser
> sudo chmod 0750 /home/doduser'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-234992'
  tag rid: 'SV-234992r1184471_rule'
  tag stig_id: 'SLES-15-040080'
  tag fix_id: 'F-38143r1184470_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  exempt_home_users = input('exempt_home_users')
  uid_min = login_defs.read_params['UID_MIN'].to_i
  uid_min = 1000 if uid_min.nil?

  iuser_entries = passwd.where { uid.to_i >= uid_min && shell !~ /nologin/ && !exempt_home_users.include?(user) }

  if !iuser_entries.users.nil? && !iuser_entries.users.empty?
    failing_homedirs = iuser_entries.homes.reject { |home|
      file(home).exist?
    }
    describe 'All non-exempt interactive user account home directories on the system' do
      it 'should exist' do
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
