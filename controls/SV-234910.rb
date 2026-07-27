control 'SV-234910' do
  title 'The SUSE operating system must generate audit records for all uses of the unix_chkpwd or unix2_chkpwd commands.'
  desc 'Without generating audit records specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Verify the SUSE operating system generates an audit record for any use of the "unix_chkpwd" or "unix2_chkpwd" commands.

Check that the commands are being audited by performing the following command:

> sudo auditctl -l | egrep -w "(unix_chkpwd|unix2_chkpwd)"

-a always,exit -S all -F path=/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-unix-chkpwd
-a always,exit -S all -F path=/sbin/unix2_chkpwd -F perm=x -F auid>=1000 -F auid!=-1 -k privileged-unix2-chkpwd

If the command does not return any output, this is a finding.

Note:
The "-k" allows for specifying an arbitrary identifier. The string following "-k" does not need to match the example output above.'
  desc 'fix', 'Configure the SUSE operating system to generate an audit record for all uses of the "unix_chkpwd" and "unix2_chkpwd" commands.

Add or update the following rules in the "/etc/audit/rules.d/audit.rules" file:

-a always,exit -F path=/sbin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-unix-chkpwd
-a always,exit -F path=/sbin/unix2_chkpwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-unix2-chkpwd

To reload the rules file, restart the audit daemon

> sudo systemctl restart auditd.service

or issue the following command:

> sudo augenrules --load'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215']
  tag gid: 'V-234910'
  tag rid: 'SV-234910r958412_rule'
  tag stig_id: 'SLES-15-030110'
  tag fix_id: 'F-38061r619000_fix'
  tag cci: ['CCI-000169', 'CCI-000130', 'CCI-000135', 'CCI-000172', 'CCI-002884']
  tag nist: ['AU-12 a', 'AU-3 a', 'AU-3 (1)', 'AU-12 c', 'MA-4 (1) (a)']
  tag 'host'

  audit_commands = ['/sbin/unix_chkpwd', '/sbin/unix2_chkpwd']

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  describe 'Command' do
    audit_commands.each do |audit_command|
      it "#{audit_command} is audited properly" do
        audit_rule = auditd.file(audit_command)
        expect(audit_rule).to exist
        expect(audit_rule.action.uniq).to cmp 'always'
        expect(audit_rule.list.uniq).to cmp 'exit'
        expect(audit_rule.fields.flatten).to include('perm=x', 'auid>=1000', 'auid!=-1')
        expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_command])
        auditctl_output = command("sudo auditctl -l | grep #{audit_command}").stdout.strip
        expect(auditctl_output).to match(/-S\s+all\b/)
      end
    end
  end
end
