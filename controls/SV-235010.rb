control 'SV-235010' do
  title 'The SUSE operating system SSH daemon must perform strict mode checking of home directory configuration files.'
  desc 'If other users have access to modify user-specific SSH configuration files, they may be able to log on to the system as another user.'
  desc 'check', %q(Verify the SUSE operating system SSH daemon performs strict mode checking of home directory configuration files.

Check that the SSH daemon performs strict mode checking of home directory configuration files with the following command:

> sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*strictmodes'

StrictModes yes

If "StrictModes" is set to "no", is missing, or the returned line is commented out, this is a finding.)
  desc 'fix', 'Configure the SUSE operating system SSH daemon performs strict mode checking of home directory configuration files.

Uncomment the "StrictModes" keyword in "/etc/ssh/sshd_config" and set the value to "yes":

StrictModes yes'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-235010'
  tag rid: 'SV-235010r991589_rule'
  tag stig_id: 'SLES-15-040260'
  tag fix_id: 'F-38161r619300_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers without SSH installed', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) || directory('/etc/ssh').exist?
  }

  describe sshd_config do
    its('StrictModes') { should cmp 'yes' }
  end
end
