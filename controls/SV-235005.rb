control 'SV-235005' do
  title 'The SUSE operating system must use a separate file system for /var.'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', 'Verify that the SUSE operating system has a separate file system/partition for "/var".

Check that a file system/partition has been created for "/var" with the following command:

> grep /var /etc/fstab
UUID=c274f65f /var ext4 noatime,nobarrier 1 2

If a separate entry for "/var" is not in use, this is a finding.'
  desc 'fix', 'Create a separate file system/partition on the SUSE operating system for "/var".

Migrate "/var" onto the separate file system/partition.'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-235005'
  tag rid: 'SV-235005r991589_rule'
  tag stig_id: 'SLES-15-040210'
  tag fix_id: 'F-38156r619285_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  describe mount('/var') do
    it { should be_mounted }
  end

  describe etc_fstab.where { mount_point == '/var' } do
    it { should exist }
  end
end
