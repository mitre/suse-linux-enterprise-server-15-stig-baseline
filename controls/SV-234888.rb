control 'SV-234888' do
  title 'The SUSE operating system must employ FIPS 140-3 approved cryptographic hashing algorithms for all stored passwords.'
  desc 'The system must use a strong hashing algorithm to store the password. The system must use a sufficient number of hashing rounds to ensure the required level of entropy.

Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

'
  desc 'check', 'Verify the SUSE operating system configures the shadow password suite configuration to encrypt passwords using a strong cryptographic hash.

Check that a minimum number of hash rounds is configured by running the following command:

> egrep "^SHA_CRYPT_" /etc/login.defs

If only one of "SHA_CRYPT_MIN_ROUNDS" or "SHA_CRYPT_MAX_ROUNDS" is set, and this value is below "100000", this is a finding.

If both "SHA_CRYPT_MIN_ROUNDS" and "SHA_CRYPT_MAX_ROUNDS" are set, and the highest value for either is below "100000", this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to encrypt all stored passwords with a strong cryptographic hash.

Edit/modify the following line in the "/etc/login.defs" file and set "SHA_CRYPT_MIN_ROUNDS" to a value no lower than "100000":

SHA_CRYPT_MIN_ROUNDS 100000'
  impact 0.5
  tag check_id: 'C-38076r1044808_chk'
  tag severity: 'medium'
  tag gid: 'V-234888'
  tag rid: 'SV-234888r1044810_rule'
  tag stig_id: 'SLES-15-020190'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-38039r1044809_fix'
  tag satisfies: ['SRG-OS-000073-GPOS-00041', 'SRG-OS-000120-GPOS-00061']
  tag 'documentable'
  tag cci: ['CCI-004062', 'CCI-000803', 'CCI-000196']
  tag nist: ['IA-5 (1) (d)', 'IA-7', 'IA-5 (1) (c)']
end
