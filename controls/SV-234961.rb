control 'SV-234961' do
  title 'The SUSE operating system audit tools must have the proper permissions configured to protect against unauthorized access.'
  desc 'Protecting audit information also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit information.

SUSE operating systems providing tools to interface with audit information will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys to make access decisions regarding the access to audit tools.

Audit tools include but are not limited to vendor-provided and open-source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'Verify that the SUSE operating system audit tools have the proper permissions configured in the permissions profile to protect from unauthorized access.

Check that "permissions.local" file contains the correct permissions rules with the following command:

> grep "^/usr/sbin/au" /etc/permissions.local

/usr/sbin/audispd root:root 0750
/usr/sbin/auditctl root:root 0750
/usr/sbin/auditd root:root 0750
/usr/sbin/ausearch root:root 0755
/usr/sbin/aureport root:root 0755
/usr/sbin/autrace root:root 0750
/usr/sbin/augenrules root:root 0750

If the command does not return any output, this is a finding.

Check that all of the audit information files and folders have the correct permissions with the following command:

> sudo chkstat /etc/permissions.local

If the command returns any output, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system audit tools to have proper permissions set in the permissions profile to protect from unauthorized access.

Edit the file "/etc/permissions.local" and insert the following text:

/usr/sbin/audispd root:root 0750
/usr/sbin/auditctl root:root 0750
/usr/sbin/auditd root:root 0750
/usr/sbin/ausearch root:root 0755
/usr/sbin/aureport root:root 0755
/usr/sbin/autrace root:root 0750
/usr/sbin/augenrules root:root 0750

Set the correct permissions with the following command:

> sudo chkstat --set /etc/permissions.local'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000256-GPOS-00097'
  tag gid: 'V-234961'
  tag rid: 'SV-234961r991557_rule'
  tag stig_id: 'SLES-15-030620'
  tag fix_id: 'F-38112r619153_fix'
  tag cci: ['CCI-001496', 'CCI-001493', 'CCI-001494', 'CCI-001495']
  tag nist: ['AU-9 (3)', 'AU-9 a', 'AU-9']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  audit_tools = %w[/usr/sbin/auditctl
                   /usr/sbin/auditd
                   /usr/sbin/ausearch
                   /usr/sbin/aureport
                   /usr/sbin/autrace
                   /usr/sbin/rsyslogd
                   /usr/sbin/augenrules]

  if package('aide').installed?
    audit_tools.each do |tool|
      describe "selection_line: #{tool}" do
        subject { aide_conf.where { selection_line.eql?(tool) } }
        its('rules.flatten') { should include 'p' }
        its('rules.flatten') { should include 'i' }
        its('rules.flatten') { should include 'n' }
        its('rules.flatten') { should include 'u' }
        its('rules.flatten') { should include 'g' }
        its('rules.flatten') { should include 's' }
        its('rules.flatten') { should include 'b' }
        its('rules.flatten') { should include 'acl' }
        its('rules.flatten') { should include 'xattrs' }
        its('rules.flatten') { should include 'sha512' }
      end
    end
  else
    describe 'The system is not utilizing Advanced Intrusion Detection Environment (AIDE)' do
      skip 'The system is not utilizing Advanced Intrusion Detection Environment (AIDE), manual review is required.'
    end
  end
end
