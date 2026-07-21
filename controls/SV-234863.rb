control 'SV-234863' do
  title 'The SUSE operating system must remove all outdated software components after updated versions have been installed.'
  desc 'Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.'
  desc 'check', 'Verify the SUSE operating system removes all outdated software components after updated version have been installed by running the following command:

> grep -i upgraderemovedroppedpackages /etc/zypp/zypp.conf

solver.upgradeRemoveDroppedPackages = true

If "solver.upgradeRemoveDroppedPackages" is commented out, is set to "false", or is missing completely, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to remove all outdated software components after an update by editing the following line in "/etc/zypp/zypp.conf" to match the one provided below:

solver.upgradeRemoveDroppedPackages = true'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000437-GPOS-00194'
  tag gid: 'V-234863'
  tag rid: 'SV-234863r958936_rule'
  tag stig_id: 'SLES-15-010560'
  tag fix_id: 'F-38014r618859_fix'
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
  tag 'host'
  tag 'container'

  describe 'Outdated package removal in /etc/zypp/zypp.conf' do
    subject { file('/etc/zypp/zypp.conf') }
    its('content') { should match(/^\s*solver\.upgradeRemoveDroppedPackages\s*=\s*true\b/i) }
  end
end
