control 'SV-234997' do
  title 'All SUSE operating system local initialization files must not execute world-writable programs.'
  desc 'If user start-up files execute world-writable programs, especially in
unprotected directories, they could be maliciously modified to destroy user
files or otherwise compromise the system at the user level. If the system is
compromised at the user level, it is easier to elevate privileges to eventually
compromise the system at the root and network level.'
  desc 'check', %q(Verify that SUSE operating system local initialization files do not execute world-writable programs.

Verify that SUSE operating system local initialization files do not
execute world-writable programs.

Check the system for world-writable files with the following command:

> sudo find / -xdev -perm -002 -type f -exec ls -ld {} \;

For all files listed, check for their presence in the local
initialization files with the following command:

Note: The example will be for a system that is configured to create
users' home directories in the "/home" directory.

> sudo find /home/* -maxdepth 1 -type f -name \.\* -exec grep -H <file> {} \;

If any local initialization files are found to reference world-writable
files, this is a finding.)
  desc 'fix', 'Remove the references to these files in the local initialization scripts or remove the world-writable permission of files referenced by SUSE operating system local initialization scripts with the following command:

> sudo chmod 0755 <file>'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-234997'
  tag rid: 'SV-234997r991589_rule'
  tag stig_id: 'SLES-15-040130'
  tag fix_id: 'F-38148r619261_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  if input('disable_slow_controls')
    describe 'This control consistently takes a long to run and has been disabled using the disable_slow_controls attribute.' do
      skip 'This control consistently takes a long to run and has been disabled using the disable_slow_controls attribute. You must enable this control for a full accredidation for production.'
    end
  else

    # get all world-writeable programs
    mount_points = etc_fstab.mount_point.join(' ')
    ww_programs = command("find #{mount_points} -xdev -type f -perm -0002 -print").stdout.split.join('|')

    # get all homedirs
    interactive_users = passwd.where { uid.to_i >= 1000 && shell !~ /nologin/ }

    interactive_user_homedirs = interactive_users.homes.map { |home_path| home_path.match(%r{^(.*)/.*$}).captures.first }.uniq

    # get all init files (.*) in homedirs
    init_files = command("find #{interactive_user_homedirs.join(' ')} -xdev -maxdepth 2 -name '.*' ! -name '.bash_history' -type f").stdout.split("\n")

    # check for ww programs in the init files
    init_files_invoking_ww = ww_programs.empty? ? [] : init_files.select { |i| file(i).content.lines.any? { |line| line.match(/^#{ww_programs}/) } }

    describe 'Interactive user initialization files' do
      it 'should not invoke world-writeable programs' do
        expect(init_files_invoking_ww).to be_empty, "Failing init files:\n\t- #{init_files_invoking_ww.join("\n\t- ")}"
      end
    end
  end
end
