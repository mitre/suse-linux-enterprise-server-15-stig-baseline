control 'SV-234890' do
  title 'The SUSE operating system must employ user passwords with a minimum lifetime of 24 hours (one day).'
  desc "Enforcing a minimum password lifetime helps prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse."
  desc 'check', %q(Verify the SUSE operating system enforces a minimum time period between password changes for each user account of one day or greater.

Check the minimum time period between password changes for each user account with the following command:

> sudo awk -F: '$4 < 1 {print $1 ":" $4}' /etc/shadow

doduser:1

If any results are returned that are not associated with a system account, this is a finding.)
  desc 'fix', 'Configure the SUSE operating system to enforce 24 hours/one day or greater as the minimum password age for user accounts.

Change the minimum time period between password changes for each [USER] account to "1" day with the command, replacing [USER] with the user account that must be changed:

> sudo passwd -n 1 [USER]'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag gid: 'V-234890'
  tag rid: 'SV-234890r1184465_rule'
  tag stig_id: 'SLES-15-020210'
  tag fix_id: 'F-38041r618940_fix'
  tag cci: ['CCI-000198', 'CCI-004066']
  tag nist: ['IA-5 (1) (d)', 'IA-5 (1) (h)']
  tag 'host'
  tag 'container'

  bad_users = users.where { uid >= 1000 }.where { mindays.to_i < 1 }.usernames
  in_scope_users = bad_users - input('exempt_home_users')

  describe 'Users should not' do
    it 'be able to change their password more than once in a 24 hour period' do
      failure_message = "The following users can update their password more than once a day: #{in_scope_users.join(', ')}"
      expect(in_scope_users).to be_empty, failure_message
    end
  end
end
