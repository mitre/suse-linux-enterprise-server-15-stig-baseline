control 'SV-234851' do
  title 'Advanced Intrusion Detection Environment (AIDE) must verify the baseline SUSE operating system configuration at least weekly.'
  desc "Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the SUSE operating system. Changes to SUSE operating system configurations can have unintended side effects, some of which may be relevant to security.

Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the SUSE operating system. The SUSE operating system's Information System Security Manager (ISSM)/Information System Security Officer (ISSO) and System Administrator (SAs) must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item."
  desc 'check', 'Verify the SUSE operating system checks the baseline configuration for unauthorized changes at least once weekly.

Note: A file integrity tool other than AIDE may be used, but the tool must be executed at least once per week.

Check for the presence of a cron job running daily or weekly on the system that executes AIDE to scan for changes to the system baseline. The command used in the following example looks at the daily cron job:

Check the "/etc/cron" subdirectories for a "crontab" file controlling the execution of the file integrity application. For example, if AIDE is installed on the system, use the following command:

     > sudo grep -R aide /etc/crontab /etc/cron.*
     /etc/crontab: 30 04 * * * /etc/aide

If the file integrity application does not exist, or a "crontab" file does not exist in "/etc/crontab", the "/etc/cron.daily" subdirectory, or "/etc/cron.weekly" subdirectory, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to check the baseline configuration for unauthorized changes at least once weekly.

If the "aide" package is not installed, install it with the following command:

     > sudo zypper in aide

Configure the file integrity tool to automatically run on the system at least weekly. The following example output is generic. It will set cron to run AIDE weekly, but other file integrity tools may be used:

     > cat /etc/cron.weekly/aide 
     0 0 * * * /usr/bin/aide --check | /bin/mail -s "$HOSTNAME - Daily AIDE integrity check run" root@example_server_name.mil

Note: Per requirement SLES-15-010418, the "mailx" package must be installed on the system to enable email functionality.'
  impact 0.5
  tag check_id: 'C-38039r880946_chk'
  tag severity: 'medium'
  tag gid: 'V-234851'
  tag rid: 'SV-234851r1184456_rule'
  tag stig_id: 'SLES-15-010420'
  tag gtitle: 'SRG-OS-000363-GPOS-00150'
  tag fix_id: 'F-38002r1184455_fix'
  tag 'documentable'
  tag cci: ['CCI-002696', 'CCI-001744', 'CCI-002699']
  tag nist: ['SI-6 a', 'CM-3 (5)', 'SI-6 b']
  tag 'host'

  file_integrity_tool = input('file_integrity_tool')

  only_if('Control not applicable within a container', impact: 0.0) do
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  end

  if file_integrity_tool == 'aide'
    describe command('/usr/sbin/aide --check') do
      its('stdout') { should_not include "Couldn't open file" }
    end
  end

  describe package(file_integrity_tool) do
    it { should be_installed }
  end
end
