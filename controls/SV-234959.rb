control 'SV-234959' do
  title 'The SUSE operating system must protect audit rules from unauthorized modification.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'Verify that the SUSE operating system protects audit rules from unauthorized modification.

Check that "permissions.local" file contains the correct permissions rules with the following command:

> grep -i audit /etc/permissions.local

/var/log/audit root:root 600
/var/log/audit/audit.log root:root 600
/etc/audit/audit.rules root:root 640
/etc/audit/rules.d/audit.rules root:root 640

If the command does not return any output, this is a finding.

Check that all of the audit information files and folders have the correct permissions with the following command:

> sudo chkstat /etc/permissions.local

If the command returns any output, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to protect audit rules from unauthorized modification.

Add or update the following rules in "/etc/permissions.local":

/var/log/audit root:root 600
/var/log/audit/audit.log root:root 600
/etc/audit/audit.rules root:root 640
/etc/audit/rules.d/audit.rules root:root 640

Set the correct permissions with the following command:

> sudo chkstat --set /etc/permissions.local'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000058-GPOS-00028', 'SRG-OS-000059-GPOS-00029']
  tag gid: 'V-234959'
  tag rid: 'SV-234959r958434_rule'
  tag stig_id: 'SLES-15-030600'
  tag fix_id: 'F-38110r619147_fix'
  tag cci: ['CCI-000162', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-9', 'AU-9 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }
  describe command('grep "^\s*[^#]" /etc/audit/audit.rules | tail -1') do
    its('stdout.strip') { should cmp '-e 2' }
  end
end
