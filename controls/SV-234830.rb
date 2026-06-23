control 'SV-234830' do
  title 'The SUSE operating system, for all network connections associated with SSH traffic, must immediately terminate at the end of the session or after 10 minutes of inactivity.'
  desc "Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the termination of network connections associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions.

Session termination terminates all processes associated with a user's logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated.

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.

This capability is typically reserved for specific SUSE operating system functionality where the system owner, data owner, or organization requires additional assurance.

In Linux, ClientAliveCountMax directive is used in the SSH daemon configuration file to define the number of client alive messages the SSH server will send without receiving any response from the client before terminating the session. The ClientAliveInterval (SLES-15-010280/ V-234827) sets a timeout interval in seconds after which if no data has been received from the client, the ssh daemon will send a message through the encrypted channel to request a response from the client. Together, these two settings provide a way to configure a timeout for inactive sessions."
  desc 'check', %q(Verify all network connections associated with SSH traffic are automatically terminated at the end of the session or after 10 minutes of inactivity.

Check that the "ClientAliveCountMax" variable is set to a value of "1" by performing the following command:

> sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*clientalivecountmax'

ClientAliveCountMax 1

If "ClientAliveCountMax" does not exist or "ClientAliveCountMax" is not set to a value of "1" in "/etc/ssh/sshd_config", or the line is commented out, this is a finding.)
  desc 'fix', 'Configure the SUSE operating system to automatically terminate all network connections associated with SSH traffic at the end of a session or after a 10-minute period of inactivity.

Modify or append the following lines in the "/etc/ssh/sshd_config" file:

ClientAliveCountMax 1

For the changes to take effect, the SSH daemon must be restarted.

> sudo systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-38018r1106555_chk'
  tag severity: 'medium'
  tag gid: 'V-234830'
  tag rid: 'SV-234830r1106556_rule'
  tag stig_id: 'SLES-15-010320'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-37981r1069399_fix'
  tag 'documentable'
  tag cci: ['CCI-001133', 'CCI-002361']
  tag nist: ['SC-10', 'AC-12']
end
