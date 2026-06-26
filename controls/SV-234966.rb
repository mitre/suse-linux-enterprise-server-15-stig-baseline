control 'SV-234966' do
  title 'The audit-audispd-plugins must be installed on the SUSE operating system.'
  desc 'The audit-audispd-plugins must be installed on the SUSE operating system.'
  desc 'check', 'Verify that the "audit-audispd-plugins" package is installed on the SUSE operating system. 

Check that the "audit-audispd-plugins" package is installed on the SUSE operating system with the following command:

> zypper info audit-audispd-plugins | grep Installed

If the "audit-audispd-plugins" package is not installed, this is a finding.'
  desc 'fix', 'Install the "audit-audispd-plugins" package on the SUSE operating system by running the following command:

> sudo zypper install audit-audispd-plugins'
  impact 0.5
  tag check_id: 'C-38154r1009562_chk'
  tag severity: 'medium'
  tag gid: 'V-234966'
  tag rid: 'SV-234966r1009564_rule'
  tag stig_id: 'SLES-15-030670'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-38117r1009563_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  describe package('audispd-plugins') do
    it { should be_installed }
  end
end
