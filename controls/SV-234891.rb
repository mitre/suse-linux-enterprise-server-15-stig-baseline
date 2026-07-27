control 'SV-234891' do
  title 'The SUSE operating system must be configured to create or update passwords with a maximum lifetime of 60 days.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the SUSE operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the SUSE operating system passwords could be compromised.'
  desc 'check', %q(Verify that the SUSE operating system is configured to create or update passwords with a maximum password age of 60 days or less.

Check that the SUSE operating system enforces 60 days or less as the maximum password age with the following command:

> grep '^PASS_MAX_DAYS' /etc/login.defs

The DOD requirement is "60" days or less (greater than zero, as zero days will lock the account immediately).

If no output is produced, or if "PASS_MAX_DAYS" is not set to "60" days or less, this is a finding.)
  desc 'fix', 'Configure the SUSE operating system to enforce a maximum password age of 60 days or less.

Edit the file "/etc/login.defs" and add or correct the following line. Replace [DAYS] with the appropriate amount of days:

PASS_MAX_DAYS [DAYS]

The DOD requirement is 60 days or less (greater than zero, as zero days will lock the account immediately).'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag gid: 'V-234891'
  tag rid: 'SV-234891r1038967_rule'
  tag stig_id: 'SLES-15-020220'
  tag fix_id: 'F-38042r986489_fix'
  tag cci: ['CCI-000199', 'CCI-004066']
  tag nist: ['IA-5 (1) (d)', 'IA-5 (1) (h)']
  tag 'host'
  tag 'container'

  value = input('pass_max_days')

  describe login_defs do
    its('PASS_MAX_DAYS') { should cmp <= value }
    its('PASS_MAX_DAYS') { should cmp > 0 }
  end
end
