control 'SV-234973' do
  title 'The SUSE operating system must generate audit records for all uses of the unlink, unlinkat, rename, renameat, and rmdir system calls.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter). The system call rules are loaded into a matching engine that intercepts each syscall made by all programs on the system. Therefore, it is very important to use syscall rules only when absolutely necessary, since these affect performance. The more rules, the bigger the performance hit. The performance can be helped, however, by combining syscalls into one rule whenever possible.'
  desc 'check', %q(Verify the SUSE operating system generates an audit record for all uses of the "unlink", "unlinkat", "rename", "renameat", and "rmdir" system calls.

Check that the system calls are being audited by performing the following command:

> sudo auditctl -l | grep 'unlink\|rename\|rmdir'

-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=-1 -k perm_mod
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=-1 -k perm_mod

If both the "b32" and "b64" audit rules are not defined for the "unlink", "unlinkat", "rename", "renameat", and "rmdir" syscalls, this is a finding.

Note:
The "-k" allows for specifying an arbitrary identifier. The string following "-k" does not need to match the example output above.)
  desc 'fix', 'Configure the SUSE operating system to generate an audit record for all uses of the "unlink", "unlinkat", "rename", "renameat", and "rmdir" system calls.

Add or update the following rules to "/etc/audit/rules.d/audit.rules":

-a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat,rmdir -F auid>=1000 -F auid!=4294967295 -k perm_mod

To reload the rules file, restart the audit daemon:

> sudo systemctl restart auditd.service

or issue the following command:

> sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-38161r809476_chk'
  tag severity: 'medium'
  tag gid: 'V-234973'
  tag rid: 'SV-234973r991577_rule'
  tag stig_id: 'SLES-15-030740'
  tag gtitle: 'SRG-OS-000468-GPOS-00212'
  tag fix_id: 'F-38124r809558_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  audit_syscalls = %w[unlink unlinkat rename renameat rmdir]

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  describe 'Syscall' do
    audit_syscalls.each do |audit_syscall|
      it "#{audit_syscall} is audited properly" do
        audit_rule = auditd.syscall(audit_syscall)
        expect(audit_rule).to exist
        expect(audit_rule.action.uniq).to cmp 'always'
        expect(audit_rule.list.uniq).to cmp 'exit'
        if os.arch.match(/64/)
          expect(audit_rule.arch.uniq).to include('b32', 'b64')
        else
          expect(audit_rule.arch.uniq).to cmp 'b32'
        end
        expect(audit_rule.fields.flatten).to include('auid>=1000', 'auid!=-1')
        expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_syscall])
      end
    end
  end
end
