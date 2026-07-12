control 'SV-251723' do
  title 'The SUSE operating system must specify the default "include" directory for the /etc/sudoers file.'
  desc 'The "sudo" command allows authorized users to run programs (including shells) as other users, system users, and root. The "/etc/sudoers" file is used to configure authorized "sudo" users as well as the programs they are allowed to run. Some configuration options in the "/etc/sudoers" file allow configured users to run programs without re-authenticating. Use of these configuration options makes it easier for one compromised account to be used to compromise other accounts.

It is possible to include other sudoers files from within the sudoers file currently being parsed using the @include and @includedir directives. For compatibility with sudo versions prior to 1.9.1, #include and #includedir are also accepted. When sudo reaches this line it will suspend processing of the current file (/etc/sudoers) and switch to the specified file/directory. Once the end of the included file(s) is reached, the rest of /etc/sudoers will be processed. Files that are included may themselves include other files. A hard limit of 128 nested include files is enforced to prevent include file loops.'
  desc 'check', 'Note: If the "include" and "includedir" directives are not present in the /etc/sudoers file, this requirement is not applicable.

Verify the operating system specifies only the default "include" directory for the /etc/sudoers file with the following command:

> sudo grep include /etc/sudoers

@includedir /etc/sudoers.d

If the results are not "/etc/sudoers.d" or additional files or directories are specified, this is a finding.

Verify the operating system does not have nested "include" files or directories within the /etc/sudoers.d directory with the following command:

> sudo grep -r include /etc/sudoers.d

If results are returned, this is a finding.'
  desc 'fix', 'Configure the /etc/sudoers file to only include the /etc/sudoers.d directory.

Edit the /etc/sudoers file with the following command:

> sudo visudo

Add or modify the following line:
@includedir /etc/sudoers.d'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-251723'
  tag rid: 'SV-251723r991589_rule'
  tag stig_id: 'SLES-15-020099'
  tag fix_id: 'F-55114r833005_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  include_directives = command('grep -i include /etc/sudoers').stdout.strip

  if include_directives.empty?
    impact 0.0
    describe 'The `include` and `includedir` directives are not present in /etc/sudoers' do
      skip 'No `include` or `includedir` directives are present in /etc/sudoers; this requirement is Not Applicable.'
    end
  else
    describe command('grep include /etc/sudoers') do
      its('stdout.strip') { should eq '@includedir /etc/sudoers.d' }
    end

    describe command('grep -r include /etc/sudoers.d') do
      its('stdout.strip') { should be_empty }
    end
  end
end
