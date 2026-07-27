control 'SV-234823' do
  title 'The SUSE operating system must disable the file system automounter.'
  desc 'Automatically mounting file systems permits easy introduction of unknown devices, thereby facilitating malicious activity.'
  desc 'check', 'Verify the SUSE operating system disables the ability to automount devices.

Check to see if automounter service is active with the following command:

> systemctl status autofs
autofs.service - Automounts filesystems on demand
Loaded: loaded (/usr/lib/systemd/system/autofs.service; disabled)
Active: inactive (dead)

If the "autofs" status is set to "active" this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to disable the ability to automount devices.

Turn off the automount service with the following commands:

> systemctl stop autofs
> systemctl disable autofs'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag gid: 'V-234823'
  tag rid: 'SV-234823r1155795_rule'
  tag stig_id: 'SLES-15-010240'
  tag fix_id: 'F-37974r1155794_fix'
  tag cci: ['CCI-000778', 'CCI-000366', 'CCI-001958']
  tag nist: ['IA-3', 'CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('autofs_required') == true
    describe systemd_service('autofs.service') do
      it { should be_running }
      it { should be_enabled }
      it { should be_installed }
    end
  elsif package('autofs').installed?
    describe systemd_service('autofs.service') do
      it { should_not be_running }
      it { should_not be_enabled }
      it { should_not be_installed }
    end
  else
    impact 0.0
    describe 'The autofs service is not installed' do
      skip 'The autofs service is not installed; this control is Not Applicable.'
    end
  end
end
