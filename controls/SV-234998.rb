control 'SV-234998' do
  title 'SUSE operating system file systems that contain user home directories must be mounted to prevent files with the setuid and setgid bit set from being executed.'
  desc 'The "nosuid" mount option causes the system to not execute setuid and setgid files with owner privileges. This option must be used for mounting any file system not containing approved setuid and setguid files. Executing files from untrusted file systems increases the opportunity for unprivileged users to attain unauthorized administrative access.'
  desc 'check', %q(Verify that SUSE operating system file systems that contain user home directories are mounted with the "nosuid" option.

Print the currently active file system mount options of the file system(s) that contain the user home directories with the following command:

> for X in `awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd`; do findmnt -nkT $X; done | sort -r
/home /dev/mapper/system-home ext4 rw,nosuid,relatime,data=ordered

If a file system containing user home directories is not mounted with the FSTYPE OPTION nosuid, this is a finding.

Note: If a separate file system has not been created for the user home directories (user home directories are mounted under "/"), this is not a finding as the "nosuid" option cannot be used on the "/" system.)
  desc 'fix', 'Configure the SUSE operating system "/etc/fstab" file to use the "nosuid" option on file systems that contain user home directories for interactive users.

Re-mount the filesystems.

> sudo mount -o remount /home'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-234998'
  tag rid: 'SV-234998r991589_rule'
  tag stig_id: 'SLES-15-040140'
  tag fix_id: 'F-38149r619264_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  option = 'nosuid'
  exempt_home_users = input('exempt_home_users')
  uid_min = login_defs.read_params['UID_MIN'].to_i
  uid_min = 1000 if uid_min.zero?

  home_dirs = passwd.where { uid.to_i >= uid_min && shell !~ /nologin/ && !exempt_home_users.include?(user) }.homes.uniq
  home_mounts = home_dirs.map { |dir| command("findmnt -nkT #{dir} -o TARGET").stdout.strip }.reject(&:empty?).uniq
  applicable_mounts = home_mounts.reject { |mnt| mnt == '/' }

  if applicable_mounts.empty?
    impact 0.0
    describe 'N/A' do
      skip 'User home directories are not on a separate file system (mounted under "/")'
    end
  else
    failing_mounts = applicable_mounts.reject { |mnt| mount(mnt).options.include?(option) }
    describe 'File systems containing user home directories' do
      it "should be mounted with '#{option}' set" do
        expect(failing_mounts).to be_empty, "Home directory file systems without '#{option}' set:\n\t- #{failing_mounts.join("\n\t- ")}"
      end
    end
  end
end
