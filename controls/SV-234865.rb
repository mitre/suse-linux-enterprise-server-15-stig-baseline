control 'SV-234865' do
  title 'The SUSE operating system must off-load rsyslog messages for networked systems in real time and off-load standalone systems at least weekly.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.'
  desc 'check', 'Verify that the SUSE operating system must off-load rsyslog messages for networked systems in real time and off-load standalone systems at least weekly.

For stand-alone hosts, verify with the system administrator that the log files are off-loaded at least weekly.

For networked systems, check that rsyslog is sending log messages to a remote server with the following command:

> sudo grep "\\*.\\*" /etc/rsyslog.conf | grep "@" | grep -v "^#"

*.*;mail.none;news.none @192.168.1.101:514

If any active message labels in the file do not have a line to send log messages to a remote server, this is a finding.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000479-GPOS-00224'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224', 'SRG-OS-000480-GPOS-00227']
  tag gid: 'V-234865'
  tag rid: 'SV-234865r1082187_rule'
  tag stig_id: 'SLES-15-010580'
  tag fix_id: 'F-38016r1069396_fix'
  tag cci: ['CCI-001851', 'CCI-000366']
  tag nist: ['AU-4 (1)', 'CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('alternative_logging_method') == ''
    describe command("grep -i 'type=\"omfwd\"' #{input('logging_conf_files').join(' ')}") do
      its('stdout') { should match(/^.*:\s*#\s*action\(\s*type\s*=\s*"omfwd"/i) }
    end
  else
    describe 'manual check' do
      skip 'Manual check required. Ask the administrator to indicate how logging is done for this system.'
    end
  end
end
