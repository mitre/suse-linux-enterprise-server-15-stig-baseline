control 'SV-234904' do
  title 'SUSE operating system audit records must contain information to establish what type of events occurred, the source of events, where events occurred, and the outcome of events.'
  desc 'Without establishing what type of events occurred, the source of events, where events occurred, and the outcome of events, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.

Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Associating event types with detected events in the SUSE operating system audit logs provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured SUSE operating system.'
  desc 'check', 'Verify the SUSE operating system produces audit records.

Check that the SUSE operating system produces audit records by running the following command to determine the current status of the auditd service:

> systemctl is-active auditd.service
active

> systemctl is-enabled auditd.service
enabled

If the service is not active or not enabled, this is a finding.'
  desc 'fix', 'Enable the SUSE operating system auditd service by performing the following commands:

> sudo systemctl enable auditd.service
> sudo systemctl start auditd.service'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000037-GPOS-00015', 'SRG-OS-000042-GPOS-00020', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000462-GPOS-00206', 'SRG-OS-000471-GPOS-00215', 'SRG-OS-000473-GPOS-00218', 'SRG-OS-000254-GPOS-00095', 'SRG-OS-000038-GPOS-00016', 'SRG-OS-000039-GPOS-00017', 'SRG-OS-000040-GPOS-00018', 'SRG-OS-000041-GPOS-00019', 'SRG-OS-000042-GPOS-00021', 'SRG-OS-000051-GPOS-00024', 'SRG-OS-000054-GPOS-00025', 'SRG-OS-000122-GPOS-00063', 'SRG-OS-000255-GPOS-00096']
  tag gid: 'V-234904'
  tag rid: 'SV-234904r958412_rule'
  tag stig_id: 'SLES-15-030050'
  tag fix_id: 'F-38055r618982_fix'
  tag cci: ['CCI-000169', 'CCI-000130', 'CCI-000135', 'CCI-000172', 'CCI-001464', 'CCI-002884', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000154', 'CCI-000158', 'CCI-001487', 'CCI-001876']
  tag nist: ['AU-12 a', 'AU-3 a', 'AU-3 (1)', 'AU-12 c', 'AU-14 (1)', 'MA-4 (1) (a)', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-6 (4)', 'AU-7 (1)', 'AU-3 f', 'AU-7 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  grub_stdout = command('grubby --info=ALL').stdout
  setting = /audit\s*=\s*1/

  describe 'GRUB config' do
    it 'should enable page poisoning' do
      expect(parse_config(grub_stdout)['args']).to match(setting), 'Current GRUB configuration does not disable this setting'
      expect(parse_config_file('/etc/default/grub')['GRUB_CMDLINE_LINUX']).to match(setting), 'Setting not configured to persist between kernel updates'
    end
  end
end
