control 'SV-234978' do
  title 'The SUSE operating system must off-load audit records onto a different system or media from the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Verify what action the audit system takes if it cannot off-load audit records to a different system or storage media from the SUSE operating system being audited.

Check the action that the audit system takes in the event of a network failure with the following command:

> sudo grep -i "network_failure_action" /etc/audit/audisp-remote.conf

network_failure_action = syslog

If the "network_failure_action" option is not set to "syslog", "single", or "halt" or the line is commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to take the appropriate action if it cannot off-load audit records to a different system or storage media from the system being audited due to a network failure.

Uncomment the "network_failure_action" option in "/etc/audit/audisp-remote.conf" and set it to "syslog", "single", or "halt". See the example below:

network_failure_action = syslog'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000479-GPOS-00224'
  tag gid: 'V-234978'
  tag rid: 'SV-234978r1009573_rule'
  tag stig_id: 'SLES-15-030790'
  tag fix_id: 'F-38129r1009572_fix'
  tag cci: ['CCI-000366', 'CCI-000154', 'CCI-001851']
  tag nist: ['CM-6 b', 'AU-6 (4)', 'AU-4 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('alternative_logging_method') == ''
    describe package('rsyslog') do
      it { should be_installed }
    end
  else
    describe 'manual check' do
      skip 'Manual check required. Ask the administrator to indicate how logging is done for this system.'
    end
  end
end
