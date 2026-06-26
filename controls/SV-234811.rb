control 'SV-234811' do
  title 'The SUSE operating system must utilize vlock to allow for session locking.'
  desc 'A session lock is a temporary action taken when a user stops work and
moves away from the immediate physical vicinity of the information system but
does not want to log out because of the temporary nature of the absence.

    The session lock is implemented at the point where session activity can be
determined.

    Regardless of where the session lock is determined and implemented, once
invoked, the session lock must remain in place until the user reauthenticates.
No other activity aside from reauthentication must unlock the system.'
  desc 'check', 'Check that the SUSE operating system has the "vlock" package installed by running the following command: 

> zypper search --installed-only --match-exact --provides vlock

If the command outputs "no matching items found", this is a finding.'
  desc 'fix', 'Allow users to lock the console by installing the "kbd" package using zypper:

> sudo zypper install kbd'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000028-GPOS-00009'
  tag satisfies: ['SRG-OS-000028-GPOS-00009', 'SRG-OS-000030-GPOS-00011', 'SRG-OS-000031-GPOS-00012']
  tag gid: 'V-234811'
  tag rid: 'SV-234811r1009610_rule'
  tag stig_id: 'SLES-15-010110'
  tag fix_id: 'F-37962r618703_fix'
  tag cci: ['CCI-000056', 'CCI-000058', 'CCI-000057', 'CCI-000060']
  tag nist: ['AC-11 b', 'AC-11 a', 'AC-11 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if package('gnome-desktop3').installed?
    describe command('gsettings get org.gnome.desktop.screensaver lock-enabled') do
      its('stdout.strip') { should cmp 'true' }
    end
  else
    impact 0.0
    describe 'The system does not have GNOME installed' do
      skip "The system does not have GNOME installed, this requirement is Not
        Applicable."
    end
  end
end
