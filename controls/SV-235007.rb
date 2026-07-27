control 'SV-235007' do
  title 'The SUSE operating system SSH daemon must be configured to not allow authentication using known hosts authentication.'
  desc 'Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere.'
  desc 'check', %q(Verify the SUSE operating system SSH daemon is configured to not allow authentication using "known hosts" authentication.

To determine how the SSH daemon's "IgnoreUserKnownHosts" option is set, run the following command:

> sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*ignoreuserknownhosts'

IgnoreUserKnownHosts yes

If the value is returned as "no", the returned line is commented out, or no output is returned, this is a finding.)
  desc 'fix', 'Configure the SUSE operating system SSH daemon to not allow authentication using "known hosts" authentication.

Add the following line in "/etc/ssh/sshd_config", or uncomment the line and set the value to "yes":

IgnoreUserKnownHosts yes'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-235007'
  tag rid: 'SV-235007r991589_rule'
  tag stig_id: 'SLES-15-040230'
  tag fix_id: 'F-38158r619291_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers without SSH installed', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) || directory('/etc/ssh').exist?
  }

  describe sshd_config do
    its('IgnoreUserKnownHosts') { should cmp 'yes' }
  end
end
