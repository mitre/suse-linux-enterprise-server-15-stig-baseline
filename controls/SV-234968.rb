control 'SV-234968' do
  title 'Audispd must off-load audit records onto a different system or media from the SUSE operating system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Verify "audispd" off-loads audit records onto a different system or media from the SUSE operating system being audited.

Check if "audispd" is configured to off-load audit records onto a different system or media from the SUSE operating system by running the following command:

> sudo grep remote_server /etc/audit/audisp-remote.conf
remote_server = 192.168.1.101

If "remote_server" is not set to an external server or media, or is commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system "/etc/audit/audisp-remote.conf" file to off-load audit records onto a different system or media by adding or editing the following line with the correct IP address:

remote_server = [IP ADDRESS]'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224']
  tag gid: 'V-234968'
  tag rid: 'SV-234968r1009570_rule'
  tag stig_id: 'SLES-15-030690'
  tag fix_id: 'F-38119r1009569_fix'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('alternative_logging_method') == ''
    describe 'rsyslog configuration' do
      subject {
        command("grep -i '^$DefaultNetstreamDriver' #{input('logging_conf_files').join(' ')} | awk -F ':' '{ print $2 }'").stdout
      }
      it { should match(/\$DefaultNetstreamDriver\s+gtls/) }
    end

    describe 'rsyslog configuration' do
      subject {
        command("grep -i '^$ActionSendStreamDriverMode' #{input('logging_conf_files').join(' ')} | awk -F ':' '{ print $2 }'").stdout
      }
      it { should match(/\$ActionSendStreamDriverMode\s+1/) }
    end
  else
    describe 'manual check' do
      skip 'Manual check required. Ask the administrator to indicate how logging is done for this system.'
    end
  end
end
