control 'SV-234864' do
  title 'The SUSE operating system must notify the System Administrator (SA) when Advanced Intrusion Detection Environment (AIDE) discovers anomalies in the operation of any security functions.'
  desc 'If anomalies are not acted on, security functions may fail to secure the system.

Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.

Notifications provided by information systems include messages to local computer consoles and/or hardware indications, such as lights.

This capability must take into account operational requirements for availability for selecting an appropriate response. The organization may choose to shut down or restart the information system upon security function anomaly detection.'
  desc 'check', 'Verify the SUSE operating system notifies the SA when AIDE discovers anomalies in the operation of any security functions.

Verify the aide cron job sends an email when executed with the following command:

     > grep -i "aide" /etc/cron.*/aide
     0 0 * * * /usr/bin/aide --check | /bin/mail -s "$HOSTNAME - Daily AIDE integrity check run" root@example_server_name.mil

If the "aide" file does not exist under the "/etc/cron" directory structure or the cron job is not configured to execute a binary to send an email (such as "/bin/mail"), this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to notify the SA when AIDE discovers anomalies in the operation of any security functions.

Create the aide crontab file in "/etc/cron.daily" and add following command replacing the "[E-MAIL]" parameter with a proper email address for the SA:

     0 0 * * * /usr/bin/aide --check | /bin/mail -s "$HOSTNAME - Daily AIDE integrity check run" root@example_server_name.mil

Note: Per requirement SLES-15-010418, the "mailx" package must be installed on the system to enable email functionality.'
  impact 0.5
  tag check_id: 'C-38052r1184460_chk'
  tag severity: 'medium'
  tag gid: 'V-234864'
  tag rid: 'SV-234864r1184462_rule'
  tag stig_id: 'SLES-15-010570'
  tag gtitle: 'SRG-OS-000447-GPOS-00201'
  tag fix_id: 'F-38015r1184461_fix'
  tag satisfies: ['SRG-OS-000363-GPOS-00150', 'SRG-OS-000446-GPOS-00200', 'SRG-OS-000447-GPOS-00201']
  tag 'documentable'
  tag cci: ['CCI-001744', 'CCI-002699', 'CCI-002702']
  tag nist: ['CM-3 (5)', 'SI-6 b', 'SI-6 d']
  tag 'host'

  file_integrity_tool = input('file_integrity_tool')

  only_if('Control not applicable within a container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  describe package(file_integrity_tool) do
    it { should be_installed }
  end
  describe.one do
    describe file("/etc/cron.daily/#{file_integrity_tool}") do
      its('content') { should match %r{/bin/mail} }
    end
    describe file("/etc/cron.weekly/#{file_integrity_tool}") do
      its('content') { should match %r{/bin/mail} }
    end
    describe crontab('root').where { command =~ /#{file_integrity_tool}/ } do
      its('commands.flatten') { should include(match %r{/bin/mail}) }
    end
    if file("/etc/cron.d/#{file_integrity_tool}").exist?
      describe crontab(path: "/etc/cron.d/#{file_integrity_tool}") do
        its('commands') { should include(match %r{/bin/mail}) }
      end
    end
  end
end
