control 'SV-234853' do
  title 'The SUSE operating system must reauthenticate users when changing authenticators, roles, or escalating privileges.'
  desc 'Without reauthentication, users may access resources or perform tasks for which they do not have authorization.

When the SUSE operating system provides the capability to change user authenticators, change security roles, or escalate a functional capability, it is critical the user reauthenticate.'
  desc 'check', %q(Verify that the SUSE operating system requires reauthentication when changing authenticators, roles, or escalating privileges.

Check that "/etc/sudoers" has no occurrences of "NOPASSWD" or "!authenticate" with the following command:

> sudo egrep -i '(nopasswd|!authenticate)' /etc/sudoers

If any uncommented lines containing "!authenticate", or "NOPASSWD" are returned and active accounts on the system have valid passwords, this is a finding.)
  desc 'fix', 'Configure the SUSE operating system to remove any occurrence of "NOPASSWD" or "!authenticate" found in the "/etc/sudoers" file. If the system does not use passwords for authentication, the "NOPASSWD" tag may exist in the file.'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00158']
  tag gid: 'V-234853'
  tag rid: 'SV-234853r1050789_rule'
  tag stig_id: 'SLES-15-010450'
  tag fix_id: 'F-38004r618829_fix'
  tag cci: ['CCI-002038', 'CCI-004895']
  tag nist: ['IA-11', 'SC-11 b']
  tag 'host'
  tag 'container-conditional'

  only_if('Control not applicable within a container without sudo installed', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) || command('sudo').exist?
  }

  describe sudoers(input('sudoers_config_files')) do
    its('settings.Defaults') { should_not include '!authenticate' }
  end

  nopasswd_lines = command('grep -rhi nopasswd /etc/sudoers /etc/sudoers.d 2>/dev/null').stdout.lines.map(&:strip).reject { |l| l.empty? || l.start_with?('#') }

  describe 'The sudoers configuration' do
    it 'should not contain any uncommented NOPASSWD entries' do
      expect(nopasswd_lines).to be_empty, "Uncommented NOPASSWD entries found:\n\t- #{nopasswd_lines.join("\n\t- ")}"
    end
  end
end
