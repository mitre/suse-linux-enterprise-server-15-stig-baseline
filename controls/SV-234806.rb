control 'SV-234806' do
  title 'The SUSE operating system must display the Standard Mandatory DoD Notice and Consent Banner until users acknowledge the usage conditions and take explicit actions to log on for further access to the local graphical user interface (GUI).'
  desc 'The SUSE operating system must display the Standard Mandatory DoD Notice and Consent Banner until users acknowledge the usage conditions and take explicit actions to log on for further access to the local graphical user interface (GUI).'
  desc 'check', 'Verify the SUSE operating system displays the Standard Mandatory DoD Notice and Consent Banner until users acknowledge the usage conditions and take explicit actions to log on via the local GUI. 

Note: If a graphical user interface is not installed, this requirement is Not Applicable.

Check the configuration by running the following command:

> more /etc/gdm/Xsession

The beginning of the file must contain the following text immediately after (#!/bin/sh):

if ! zenity --text-info \\
--title "Consent" \\
--filename=/etc/gdm/banner \\
--no-markup \\
--checkbox="Accept." 10 10; then
sleep 1;
exit 1;
fi

If the beginning of the file does not contain the above text immediately after the line (#!/bin/sh), this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to display the Standard Mandatory DoD Notice and Consent Banner until users acknowledge the usage conditions and take explicit actions to log on for further access.

Note: If a graphical user interface is not installed, this requirement is Not Applicable.

Edit the file "/etc/gdm/Xsession".

Add the following content to the file "/etc/gdm/Xsession" below the line #!/bin/sh:

if ! zenity --text-info \\
--title "Consent" \\
--filename=/etc/gdm/banner \\
--no-markup \\
--checkbox="Accept." 10 10; then
sleep 1;
exit 1;
fi

Save the file "/etc/gdm/Xsession".'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag satisfies: ['SRG-OS-000023-GPOS-00006', 'SRG-OS-000228-GPOS-00088', 'SRG-OS-000024-GPOS-00007']
  tag gid: 'V-234806'
  tag rid: 'SV-234806r958390_rule'
  tag stig_id: 'SLES-15-010050'
  tag fix_id: 'F-37957r618688_fix'
  tag cci: ['CCI-000048', 'CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388', 'CCI-000050']
  tag nist: ['AC-8 a', 'AC-8 c 1', 'AC-8 c 2', 'AC-8 c 3', 'AC-8 b']
  tag 'host'

  only_if('This requirement is Not Applicable in the container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  no_gui = command('ls /usr/share/xsessions/*').stderr.match?(/No such file or directory/)

  if no_gui
    impact 0.0
    describe 'The system does not have a GUI Desktop is installed; this control is Not Applicable' do
      skip 'A GUI desktop is not installed; this control is Not Applicable.'
    end
  else
    output = command('gsettings get org.gnome.login-screen banner-message-enable').stdout.strip
    describe 'A banner message should be displayed on the login screen' do
      subject { output }
      it { should cmp 'true' }
    end
  end
end
