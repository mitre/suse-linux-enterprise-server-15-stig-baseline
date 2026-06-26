control 'SV-234991' do
  title 'All SUSE operating system local interactive users must have a home directory assigned in the /etc/passwd file.'
  desc 'If local interactive users are not assigned a valid home directory,
there is no place for the storage and control of files they should own.'
  desc 'check', %q(Verify SUSE operating system local interactive users on the system have a home directory assigned.

Check for missing local interactive user home directories with the following command:

> sudo pwck -r
user 'doduser': directory '/home/doduser' does not exist

Ask the system administrator (SA) if any users found without home directories are local interactive users. If the SA is unable to provide a response, check for users with a User Identifier (UID) of 1000 or greater with the following command:

> awk -F: '($3>=1000)&&($1!="nobody"){print $1 ":" $3}' /etc/passwd

If any interactive users do not have a home directory assigned, this is a finding.)
  desc 'fix', 'Assign home directories to all SUSE operating system local interactive users that currently do not have a home directory assigned.

Assign a home directory to users via the usermod command:

> sudo usermod -d /home/doduser doduser'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-234991'
  tag rid: 'SV-234991r1184468_rule'
  tag stig_id: 'SLES-15-040070'
  tag fix_id: 'F-38142r1184467_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  exempt_users = input('exempt_home_users')
  ignore_shells = input('non_interactive_shells').join('|')
  actvite_users_without_homedir = users.where { !shell.match(ignore_shells) && home.nil? }.entries

  # only_if("This control is Not Applicable since no 'non-exempt' users were found", impact: 0.0) { !active_home.empty? }

  describe 'All non-exempt users' do
    it 'have an assinded home directory that exists' do
      failure_message = "The following users do not have an assigned home directory: #{actvite_users_without_homedir.join(', ')}"
      expect(actvite_users_without_homedir).to be_empty, failure_message
    end
  end
  describe 'Note: `exempt_home_users` skipped user' do
    exempt_users.each do |u|
      next if exempt_users.empty?

      it u.to_s do
        expect(user(u).username).to be_truthy.or be_nil
      end
    end
  end
end
