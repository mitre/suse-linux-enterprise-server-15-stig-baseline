control 'SV-234813' do
  title 'The SUSE operating system must initiate a session lock after a 10-minute period of inactivity.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. 

Rather than relying on the users to manually lock their SUSE operating system session prior to vacating the vicinity, the SUSE operating system needs to be able to identify when a user's session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled."
  desc 'check', 'Verify the SUSE operating system must initiate a session logout after a 10-minute period of inactivity for all connection types. 

Check the proper script exists to kill an idle session after a 10-minute period of inactivity with the following command:

> cat /etc/profile.d/autologout.sh
TMOUT=600
readonly TMOUT
export TMOUT

If the file "/etc/profile.d/autologout.sh" does not exist or the output from the function call is not the same, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to initiate a session lock after a 10-minute period of inactivity by modifying or creating (if it does not already exist) the "/etc/profile.d/autologout.sh" file and add the following lines to it:

TMOUT=600
readonly TMOUT
export TMOUT

Set the proper permissions for the "/etc/profile.d/autologout.sh" file with the following command:

> sudo chmod +x /etc/profile.d/autologout.sh'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag satisfies: ['SRG-OS-000029-GPOS-00010', 'SRG-OS-000031-GPOS-00012', 'SRG-OS-000480-GPOS-00227']
  tag gid: 'V-234813'
  tag rid: 'SV-234813r1009561_rule'
  tag stig_id: 'SLES-15-010130'
  tag fix_id: 'F-37964r1009560_fix'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if package('gnome-desktop3').installed?
    output = command('gsettings writable org.gnome.desktop.screensaver lock-delay').stdout.strip
    describe 'Users should not be able to override GUI settings' do
      subject { output }
      it { should cmp 'false' }
    end
  else
    impact 0.0
    describe 'The GNOME desktop is not installed' do
      skip 'The GNOME desktop is not installed; this control is Not Applicable.'
    end
  end
end
