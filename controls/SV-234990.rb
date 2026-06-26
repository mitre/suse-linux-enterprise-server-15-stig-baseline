control 'SV-234990' do
  title 'The SUSE operating system must disable the systemd Ctrl-Alt-Delete burst key sequence.'
  desc 'A locally logged-on user, who presses Ctrl-Alt-Delete when at the console, can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot. In the graphical user interface environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.'
  desc 'check', 'Verify the SUSE operating system is not configured to reboot the system when Ctrl-Alt-Delete is pressed seven times within two seconds with the following command:

> systemd-analyze cat-config systemd/system.conf

# /etc/systemd/system.conf.d/55-CtrlAltDel-BurstAction.conf
CtrlAltDelBurstAction=none

If the "CtrlAltDelBurstAction" is not set to "none", commented out, or is missing, this is a finding.
If the setting is not configured in a drop in file, this is a finding.'
  desc 'fix', 'Configure the system to disable the CtrlAltDelBurstAction by adding it to a drop file in a "/etc/systemd/system.conf.d/" configuration file:

If no drop file exists, create one with the following command:

> sudo touch /etc/systemd/system.conf.d/55-CtrlAltDel-BurstAction

Edit the file to contain the setting by adding the following text:

CtrlAltDelBurstAction=none

Reload the daemon for this change to take effect:

> sudo systemctl daemon-reexec'
  impact 0.7
  tag check_id: 'C-38178r1102123_chk'
  tag severity: 'high'
  tag gid: 'V-234990'
  tag rid: 'SV-234990r1106565_rule'
  tag stig_id: 'SLES-15-040062'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-38141r1102124_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('Control not applicable within a container without sudo enabled', impact: 0.0) do
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  end

  grubby = command('grubby --info=ALL').stdout

  describe parse_config(grubby) do
    its('args') { should_not include 'systemd.confirm_spawn' }
  end
end
