control 'SV-235031' do
  title 'The SUSE operating system must not allow unattended or automatic logon via the graphical user interface (GUI).'
  desc 'Failure to restrict system access to authenticated users negatively impacts SUSE operating system security.'
  desc 'check', 'Note: If a graphical user interface is not installed, this requirement is Not Applicable.

Verify the SUSE operating system does not allow unattended or automatic logon via the GUI.

Check that unattended or automatic login is disabled with the following commands:

> grep -i ^DISPLAYMANAGER_AUTOLOGIN /etc/sysconfig/displaymanager

DISPLAYMANAGER_AUTOLOGIN=""

> grep -i ^DISPLAYMANAGER_PASSWORD_LESS_LOGIN /etc/sysconfig/displaymanager

DISPLAYMANAGER_PASSWORD_LESS_LOGIN="no"

If the "DISPLAYMANAGER_AUTOLOGIN" parameter includes a username or the
"DISPLAYMANAGER_PASSWORD_LESS_LOGIN"
If parameter is not set to "no", this is a finding.'
  desc 'fix', 'Note: If a graphical user interface is not installed, this requirement is Not Applicable.

Configure the SUSE operating system GUI to not allow unattended or automatic logon to the system.

Add or edit the following lines in the "/etc/sysconfig/displaymanager"
configuration file:

DISPLAYMANAGER_AUTOLOGIN=""
DISPLAYMANAGER_PASSWORD_LESS_LOGIN="no"'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag gid: 'V-235031'
  tag rid: 'SV-235031r991591_rule'
  tag stig_id: 'SLES-15-040430'
  tag fix_id: 'F-38182r619363_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This requirement is Not Applicable inside a container, the containers host manages the containers filesystems') {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  custom_conf = '/etc/gdm/custom.conf'

  if package('gnome-desktop3').installed?
    if (f = file(custom_conf)).exist?
      describe parse_config_file(custom_conf) do
        its('daemon.AutomaticLoginEnable') { cmp false }
      end
    else
      describe f do
        it { should exist }
      end
    end
  else
    impact 0.0
    describe 'The system does not have GDM installed' do
      skip 'The system does not have GDM installed, this requirement is Not Applicable.'
    end
  end
end
