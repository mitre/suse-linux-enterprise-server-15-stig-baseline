control 'SV-235003' do
  title 'SUSE operating system kernel core dumps must be disabled unless needed.'
  desc 'Kernel core dumps may contain the full contents of system memory at the time of the crash. Kernel core dumps may consume a considerable amount of disk space and may result in denial of service by exhausting the available space on the target file system partition.'
  desc 'check', 'Verify that SUSE operating system kernel core dumps are disabled unless needed.

Check the status of the "kdump" service with the following command:

> systemctl status kdump.service
Loaded: not-found (Reason: No such file or directory)
Active: inactive (dead)

If the "kdump" service is active, ask the System Administrator if the use of the service is required and documented with the Information System Security Officer (ISSO).

If the service is active and is not documented, this is a finding.'
  desc 'fix', 'If SUSE operating system kernel core dumps are not required, disable the "kdump" service with the following command:

> sudo systemctl disable kdump.service

If kernel core dumps are required, document the need with the ISSO.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-235003'
  tag rid: 'SV-235003r991589_rule'
  tag stig_id: 'SLES-15-040190'
  tag fix_id: 'F-38154r619279_fix'
  tag cci: ['CCI-000366']
  tag legacy: []
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('core_dumps_required')
    impact 0.0
    describe 'N/A' do
      skip "Profile inputs indicate that this parameter's setting is a documented operational requirement"
    end
  else
    describe service('kdump') do
      it { should_not be_running }
      it { should_not be_enabled }
    end
  end
end
