control 'SV-234995' do
  title 'All SUSE operating system local initialization files must have mode 0740 or less permissive.'
  desc "Local initialization files are used to configure the user's shell environment upon logon. Malicious modification of these files could compromise accounts upon logon."
  desc 'check', 'Verify that all SUSE operating system local initialization files have a mode of "0740" or less permissive.

Check the mode on all SUSE operating system local initialization files with the following command:

Note: The example will be for the user "doduser", who has a home directory of "/home/doduser".

> sudo ls -al /home/doduser/.* | more
-rwxr-xr-x 1 doduser users 896 Mar 10 2011 .profile
-rwxr-xr-x 1 doduser users 497 Jan 6 2007 .login
-rwxr-xr-x 1 doduser users 886 Jan 6 2007 .something

If any local initialization files have a mode more permissive than "0740", this is a finding.'
  desc 'fix', 'Set the mode of SUSE operating system local initialization files to "0740" with the following command:

Note: The example will be for the doduser user, who has a home directory of "/home/doduser".

> sudo chmod 0740 /home/doduser/.<INIT_FILE>'
  impact 0.5
  tag check_id: 'C-38183r1184478_chk'
  tag severity: 'medium'
  tag gid: 'V-234995'
  tag rid: 'SV-234995r1184480_rule'
  tag stig_id: 'SLES-15-040110'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-38146r1184479_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
