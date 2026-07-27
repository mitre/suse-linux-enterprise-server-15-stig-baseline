control 'SV-235028' do
  title 'All SUSE operating system files and directories must have a valid owner.'
  desc 'Unowned files and directories may be unintentionally inherited if a user is assigned the same User Identifier (UID) as the UID of the unowned files.'
  desc 'check', 'Verify that all SUSE operating system files and directories on the system have a valid owner.

Check the owner of all files and directories with the following command:

Note: The value after -fstype must be replaced with the filesystem type. XFS is used as an example.

> sudo find / -fstype xfs -nouser

If any files on the system do not have an assigned owner, this is a finding.'
  desc 'fix', 'Either remove all files and directories from the SUSE operating system that do not have a valid user, or assign a valid user to all unowned files and directories on the system with the "chown" command:

> sudo chown <user> <file>'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-235028'
  tag rid: 'SV-235028r991589_rule'
  tag stig_id: 'SLES-15-040400'
  tag fix_id: 'F-38179r619354_fix'
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
      failing_files += command("find / -xdev -xautofs -fstype #{fs} -nouser").stdout.strip.split("\n")
    end

    describe 'All local files and directories' do
      it 'should have an owner' do
        expect(failing_files).to be_empty, "Files with no owner:\n\t- #{failing_files.join("\n\t- ")}"
      end
    end
  end
end
