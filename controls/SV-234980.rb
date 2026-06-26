control 'SV-234980' do
  title 'The SUSE operating system must use a separate file system for the system audit data path.'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', 'Verify that the SUSE operating system has a separate file system/partition for the system audit data path.

Check that a file system/partition has been created for the system audit data path with the following command:

Note: "/var/log/audit" is used as the example as it is a common location.

> grep /var/log/audit /etc/fstab
UUID=3645951a /var/log/audit ext4 defaults 1 2

If a separate entry for the system audit data path (in this example the "/var/log/audit" path) does not exist, ask the System Administrator if the system audit logs are being written to a different file system/partition on the system and then grep for that file system/partition. 

If a separate file system/partition does not exist for the system audit data path, this is a finding.'
  desc 'fix', 'Migrate the SUSE operating system audit data path onto a separate file system.'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-234980'
  tag rid: 'SV-234980r991589_rule'
  tag stig_id: 'SLES-15-030810'
  tag fix_id: 'F-38131r619210_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  describe mount('/tmp') do
    it { should be_mounted }
  end

  describe etc_fstab.where { mount_point == '/tmp' } do
    it { should exist }
  end
end
