control 'SV-274879' do
  title 'The SUSE operating system must audit any script or executable called by cron as root or by any privileged user.'
  desc 'Any script or executable called by cron as root or by any privileged user must be owned by that user, must have the permissions 755 or more restrictive, and have no extended rights that allow any nonprivileged user to modify the script or executable.'
  desc 'check', 'Verify the SUSE operating system is configured to audit the execution of any system call made by cron as root or as any privileged user.

> sudo auditctl -l | grep /etc/cron.d
-w /etc/cron.d -p wa -k cronjobs

$ sudo auditctl -l | grep /var/spool/cron
-w /var/spool/cron -p wa -k cronjobs

If either of these commands do not return the expected output, or the lines are commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to audit the execution of any system call made by cron as root or as any privileged user.

Add or update the following file system rules to "/etc/audit/rules.d/audit.rules":

auditctl -w /etc/cron.d/ -p wa -k cronjobs
auditctl -w /var/spool/cron/ -p wa -k cronjobs

To load the rules to the kernel immediately, use the following command:

> sudo augenrules --load'
  impact 0.5
  tag check_id: 'C-78980r1102126_chk'
  tag severity: 'medium'
  tag gid: 'V-274879'
  tag rid: 'SV-274879r1106564_rule'
  tag stig_id: 'SLES-15-030015'
  tag gtitle: 'SRG-OS-000471-GPOS-00215'
  tag fix_id: 'F-78885r1102127_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  audit_paths = ['/etc/cron.d', '/var/spool/cron']

  describe 'Cron directories auditing' do
    audit_paths.each do |audit_path|
      it "#{audit_path} is audited properly" do
        audit_rule = auditd.file(audit_path)
        expect(audit_rule).to exist
        expect(audit_rule.permissions.flatten).to include('w', 'a')
        expect(audit_rule.key.uniq).to include(input('audit_rule_keynames').merge(input('audit_rule_keynames_overrides'))[audit_path])
      end
    end
  end
end
