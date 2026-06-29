control 'SV-234967' do
  title 'The SUSE operating system audit event multiplexor must be configured to use Kerberos.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Allowing devices and users to connect to or from the system without first authenticating them allows untrusted access and can lead to a compromise or attack. Audit events that may include sensitive data must be encrypted prior to transmission. Kerberos provides a mechanism to provide both authentication and encryption for audit event records.'
  desc 'check', 'Determine if the SUSE operating system audit event multiplexor is configured to use Kerberos by running the following command:

> sudo grep transport /etc/audit/audisp-remote.conf
transport = krb5

If "transport" is not set to "krb5", or is commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system audit event multiplexor to use Kerberos by editing the "/etc/audit/audisp-remote.conf" file.

Edit or add the following line to match the text below:

transport = krb5'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224']
  tag gid: 'V-234967'
  tag rid: 'SV-234967r1009567_rule'
  tag stig_id: 'SLES-15-030680'
  tag fix_id: 'F-38118r1009566_fix'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('alternative_logging_method') == ''
    describe parse_config_file('/etc/audit/auditd.conf') do
      its('overflow_action') { should match(/syslog$|single$|halt$/i) }
    end
  else
    describe 'manual check' do
      skip 'Manual check required. Ask the administrator to indicate how logging is done for this system.'
    end
  end
end
