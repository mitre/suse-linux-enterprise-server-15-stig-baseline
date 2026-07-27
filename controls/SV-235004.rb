control 'SV-235004' do
  title 'A separate file system must be used for SUSE operating system user home directories (such as /home or an equivalent).'
  desc 'The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.'
  desc 'check', "Verify that a separate file system/partition has been created for SUSE operating system nonprivileged local interactive user home directories.

Check the home directory assignment for all nonprivileged users (those with a UID greater than 1000) on the system with the following command:

> awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6, $7}' /etc/passwd

disauser 1002 /home/disauser /bin/bash
doduser 1003 /home/doduser /bin/bash
doduser 1001 /home/doduser /bin/bash

The output of the command will give the directory/partition that contains the home directories for the nonprivileged users on the system (in this example, /home) and user's shell. All accounts with a valid shell (such as /bin/bash) are considered interactive users.

Check that a file system/partition has been created for the nonprivileged interactive users with the following command:

Note: The partition of /home is used in the example.

> grep /home /etc/fstab
UUID=333ada18 /home ext4 noatime,nobarrier,nodev 1 2

If a separate entry for the file system/partition that contains the nonprivileged interactive users' home directories does not exist, this is a finding."
  desc 'fix', 'Create a separate file system/partition for SUSE operating system nonprivileged local interactive user home directories.

Migrate the nonprivileged local interactive user home directories onto the separate file system/partition.'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-235004'
  tag rid: 'SV-235004r1184485_rule'
  tag stig_id: 'SLES-15-040200'
  tag fix_id: 'F-38155r1184484_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This requirement is Not Applicable inside a container; the host manages the container filesystem') {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  ignore_shells = input('non_interactive_shells').join('|')
  homes = users.where { uid >= 1000 && !shell.match(ignore_shells) }.homes
  root_device = etc_fstab.where { mount_point == '/' }.device_name

  if input('exempt_separate_filesystem')
    impact 0.0
    describe 'This system is not required to have separate filesystems for each mount point' do
      skip 'The system is managing filesystems and space via other mechanisms; this requirement is Not Applicable'
    end
  else
    homes.each do |home|
      pn_parent = Pathname.new(home).parent.to_s
      home_device = etc_fstab.where { mount_point == pn_parent }.device_name

      describe "The '#{pn_parent}' mount point" do
        subject { home_device }

        it 'is not on the same partition as the root partition' do
          is_expected.not_to equal(root_device)
        end

        it 'has its own partition' do
          is_expected.not_to be_empty
        end
      end
    end
  end
end
