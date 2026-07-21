control 'SV-234956' do
  title 'The Information System Security Officer (ISSO) and System Administrator (SA), at a minimum, must be alerted of a SUSE operating system audit processing failure event.'
  desc 'It is critical for the appropriate personnel to be aware if a system
is at risk of failing to process audit logs as required. Without this
notification, the security personnel may be unaware of an impending failure of
the audit capability, and system operation may be adversely affected.

    Audit processing failures include software/hardware errors, failures in the
audit capturing mechanisms, and audit storage capacity being reached or
exceeded.

    This requirement applies to each audit data storage repository (i.e.,
distinct information system component where audit records are stored), the
centralized audit storage capacity of organizations (i.e., all audit data
storage repositories combined), or both.'
  desc 'check', 'Verify the administrators are notified in the event of a SUSE operating system audit processing failure by inspecting "/etc/audit/auditd.conf".

Check if the system is configured to send email to an account when it needs to notify an administrator with the following command:

> sudo grep action_mail /etc/audit/auditd.conf

action_mail_acct = root

If the value of the "action_mail_acct" keyword is not set to "root" and/or other accounts for security personnel, the "action_mail_acct" keyword is missing, or the returned line is commented out, this is a finding.'
  desc 'fix', 'Configure the auditd service to notify the administrators in the event of a SUSE operating system audit processing failure.

Edit the following line in "/etc/audit/auditd.conf" to ensure that administrators are notified via email for those situations:

action_mail_acct = root'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000046-GPOS-00022'
  tag gid: 'V-234956'
  tag rid: 'SV-234956r958424_rule'
  tag stig_id: 'SLES-15-030570'
  tag fix_id: 'F-38107r619138_fix'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  alternative_logging = input('alternative_logging')

  if alternative_logging == true
    describe 'Alternative logging' do
      it 'should handle sysadmin and ISSO notification' do
        expect(alternative_logging).to eq(true)
      end
    end
  else
    describe auditd_conf do
      its('action_mail_acct') { should cmp input('action_mail_acct') }
    end
  end
end
