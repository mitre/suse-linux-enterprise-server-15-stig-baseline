control 'SV-234963' do
  title 'The SUSE operating system must generate audit records for all uses of the privileged functions.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.'
  desc 'check', %q(Verify the SUSE operating system generates an audit record for any privileged use of the "execve" system call.

> sudo auditctl -l | grep -w 'execve'

-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k setuid
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid
-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k setgid
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k setgid

If both the "b32" and "b64" audit rules for "SUID" files are not defined, this is a finding.

If both the "b32" and "b64" audit rules for "SGID" files are not defined, this is a finding.

Note: The "-k" allows for specifying an arbitrary identifier. The string following "-k" does not need to match the example output above.)
  desc 'fix', 'Configure the SUSE operating system to generate an audit record for any privileged use of the "execve" system call.

Add or update the following rules in "/etc/audit/rules.d/audit.rules":

-a always,exit -F arch=b32 -S execve -C uid!=euid -F euid=0 -k setuid
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k setuid
-a always,exit -F arch=b32 -S execve -C gid!=egid -F egid=0 -k setgid
-a always,exit -F arch=b64 -S execve -C gid!=egid -F egid=0 -k setgid

To reload the rules file, restart the audit daemon:

> sudo systemctl restart auditd.service

or issue the following command:

> sudo augenrules --load'
  impact 0.3
  tag check_id: 'C-38151r986508_chk'
  tag severity: 'low'
  tag gid: 'V-234963'
  tag rid: 'SV-234963r1009638_rule'
  tag stig_id: 'SLES-15-030640'
  tag gtitle: 'SRG-OS-000327-GPOS-00127'
  tag fix_id: 'F-38114r986509_fix'
  tag 'documentable'
  tag cci: ['CCI-000172', 'CCI-003938', 'CCI-001875', 'CCI-001877', 'CCI-001878', 'CCI-001879', 'CCI-001880', 'CCI-001881', 'CCI-001882', 'CCI-001889', 'CCI-001914', 'CCI-002234', 'CCI-001814']
  tag nist: ['AU-12 c', 'CM-5 (1) (b)', 'AU-7 a', 'AU-7 b', 'AU-8 b', 'AU-12 (3)', 'AC-6 (9)', 'CM-5 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  # execve is audited for setuid (uid!=euid, euid=0) and setgid (gid!=egid, egid=0) privilege escalation.
  describe 'Syscall execve (setuid/setgid)' do
    subject { auditd.syscall('execve') }
    it { should exist }
    its('action.uniq') { should cmp 'always' }
    its('list.uniq') { should cmp 'exit' }
    its('fields.flatten') { should include('uid!=euid', 'euid=0', 'gid!=egid', 'egid=0') }
    its('key.uniq') { should include('setuid', 'setgid') }
  end
end
