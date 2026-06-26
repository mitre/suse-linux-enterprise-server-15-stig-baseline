control 'SV-234870' do
  title 'The SUSE operating system must deny direct logons to the root account using remote access via SSH.'
  desc 'To ensure individual accountability and prevent unauthorized access, organizational users must be individually identified and authenticated.

A group authenticator is a generic account used by multiple individuals. Use of a group authenticator alone does not uniquely identify individual users. Examples of the group authenticator is the UNIX OS "root" user account, the Windows "Administrator" account, the "sa" account, or a "helpdesk" account.

For example, the UNIX and Windows SUSE operating systems offer a "switch user" capability, allowing users to authenticate with their individual credentials and, when needed, "switch" to the administrator role. This method provides for unique individual authentication prior to using a group authenticator.

Users (and any processes acting on behalf of users) need to be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization, which outlines specific user actions that can be performed on the SUSE operating system without identification or authentication.

Requiring individuals to be authenticated with an individual authenticator prior to using a group authenticator allows for traceability of actions, as well as adding an additional level of protection of the actions that can be taken with group account knowledge.'
  desc 'check', %q(Verify the SUSE operating system denies direct logons to the root account using remote access via SSH.

Check that SSH denies any user trying to log on directly as root with the following command:

> sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*permitrootlogin'

PermitRootLogin no

If the "PermitRootLogin" keyword is set to "yes", is missing, or is commented out, this is a finding.)
  desc 'fix', 'Configure the SUSE operating system to deny direct logons to the root account using remote access via SSH.

Edit the appropriate "/etc/ssh/sshd_config" file, add or uncomment the line for "PermitRootLogin" and set its value to "no" (this file may be named differently or be in a different location):

PermitRootLogin no'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000109-GPOS-00056'
  tag gid: 'V-234870'
  tag rid: 'SV-234870r1009618_rule'
  tag stig_id: 'SLES-15-020040'
  tag fix_id: 'F-38021r618880_fix'
  tag cci: ['CCI-000770', 'CCI-000366', 'CCI-004045']
  tag nist: ['IA-2 (5)', 'CM-6 b']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers without SSH installed', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) || directory('/etc/ssh').exist?
  }

  describe sshd_config do
    its('PermitRootLogin') { should cmp input('permit_root_login') }
  end
end
