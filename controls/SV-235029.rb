control 'SV-235029' do
  title 'All SUSE operating system files and directories must have a valid group owner.'
  desc 'Files without a valid group owner may be unintentionally inherited if
a group is assigned the same Group Identifier (GID) as the GID of the files
without a valid group owner.'
  desc 'check', 'Verify all SUSE operating system files and directories on the system have a valid group.

Check the owner of all files and directories with the following command:

Note: The value after -fstype must be replaced with the filesystem type. XFS is used as an example.

> sudo find / -fstype xfs -nogroup

If any files on the system do not have an assigned group, this is a finding.'
  desc 'fix', 'Either remove all files and directories from the SUSE operating system that do not have a valid group, or assign a valid group to all files and directories on the system with the "chgrp" command:

> sudo chgrp <group> <file>'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-235029'
  tag rid: 'SV-235029r991589_rule'
  tag stig_id: 'SLES-15-040410'
  tag fix_id: 'F-38180r619357_fix'
  tag cci: ['CCI-000366', 'CCI-001230']
  tag nist: ['CM-6 b', 'SI-2 d']
  tag 'host'
  tag 'container'

  if input('disable_slow_controls')
    describe 'This control consistently takes a long to run and has been disabled using the disable_slow_controls attribute.' do
      skip 'This control consistently takes a long to run and has been disabled using the disable_slow_controls attribute. You must enable this control for a full accredidation for production.'
    end
  else

    failing_files = Set[]

    command('grep -v "nodev" /proc/filesystems | awk \'NF{ print $NF }\'')
      .stdout.strip.split("\n").each do |fs|
      failing_files += command("find / -xdev -xautofs -fstype #{fs} -nogroup").stdout.strip.split("\n")
    end

    describe 'All files on RHEL 9' do
      it 'should have a group' do
        expect(failing_files).to be_empty, "Files with no group:\n\t- #{failing_files.join("\n\t- ")}"
      end
    end
  end
end
