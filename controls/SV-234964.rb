control 'SV-234964' do
  title 'The SUSE operating system must have the auditing package installed.'
  desc 'Without establishing what type of events occurred, the source of events, where events occurred, and the outcome of events, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the SUSE operating system audit logs provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured SUSE operating system.'
  desc 'check', 'Verify the SUSE operating system auditing package is installed.

Check that the "audit" package is installed by performing the following command:

> zypper info audit | grep Installed

i | audit | User Space Tools for 2.6 Kernel Auditing

If the package "audit" is not installed on the system, then this is a finding.'
  desc 'fix', 'The SUSE operating system auditd package must be installed on the system. If it is not installed, use the following command to install it:

> sudo zypper in audit'
  impact 0.5
  tag check_id: 'C-38152r619161_chk'
  tag severity: 'medium'
  tag gid: 'V-234964'
  tag rid: 'SV-234964r1009639_rule'
  tag stig_id: 'SLES-15-030650'
  tag gtitle: 'SRG-OS-000337-GPOS-00129'
  tag fix_id: 'F-38115r619162_fix'
  tag 'documentable'
  tag cci: ['CCI-002235', 'CCI-000172', 'CCI-003938', 'CCI-001875', 'CCI-001877', 'CCI-001878', 'CCI-001879', 'CCI-001880', 'CCI-001881', 'CCI-001882', 'CCI-001889', 'CCI-001914', 'CCI-001814']
  tag nist: ['AC-6 (10)', 'AU-12 c', 'CM-5 (1) (b)', 'AU-7 a', 'AU-7 b', 'AU-8 b', 'AU-12 (3)', 'CM-5 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) || file('/etc/ssh/sshd_config').exist?
  }

  describe package('sudo') do
    it { should be_installed }
  end
end
