control 'SV-234888' do
  title 'The SUSE operating system must employ FIPS 140-3 approved cryptographic hashing algorithms for all stored passwords.'
  desc 'The system must use a strong hashing algorithm to store the password. The system must use a sufficient number of hashing rounds to ensure the required level of entropy.

Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.'
  desc 'check', 'Verify the SUSE operating system configures the shadow password suite configuration to encrypt passwords using a strong cryptographic hash.

Check that a minimum number of hash rounds is configured by running the following command:

> egrep "^SHA_CRYPT_" /etc/login.defs

If only one of "SHA_CRYPT_MIN_ROUNDS" or "SHA_CRYPT_MAX_ROUNDS" is set, and this value is below "100000", this is a finding.

If both "SHA_CRYPT_MIN_ROUNDS" and "SHA_CRYPT_MAX_ROUNDS" are set, and the highest value for either is below "100000", this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to encrypt all stored passwords with a strong cryptographic hash.

Edit/modify the following line in the "/etc/login.defs" file and set "SHA_CRYPT_MIN_ROUNDS" to a value no lower than "100000":

SHA_CRYPT_MIN_ROUNDS 100000'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag gid: 'V-234888'
  tag rid: 'SV-234888r1044810_rule'
  tag stig_id: 'SLES-15-020190'
  tag fix_id: 'F-38039r1044809_fix'
  tag cci: ['CCI-000803', 'CCI-000196', 'CCI-004062']
  tag nist: ['IA-7', 'IA-5 (1) (c)', 'IA-5 (1) (d)']
  tag 'host'
  tag 'container'

  min_rounds = login_defs.read_params['SHA_CRYPT_MIN_ROUNDS']
  max_rounds = login_defs.read_params['SHA_CRYPT_MAX_ROUNDS']
  configured_rounds = [min_rounds, max_rounds].compact
  required_rounds = input('password_hash_rounds')

  describe 'The SHA_CRYPT rounds configuration in /etc/login.defs' do
    it 'should set SHA_CRYPT_MIN_ROUNDS and/or SHA_CRYPT_MAX_ROUNDS' do
      expect(configured_rounds).not_to be_empty, 'Neither SHA_CRYPT_MIN_ROUNDS nor SHA_CRYPT_MAX_ROUNDS is set in /etc/login.defs'
    end
    it "should have a highest configured rounds value of at least #{required_rounds}" do
      highest = configured_rounds.map(&:to_i).max || 0
      expect(highest).to be >= required_rounds, "The highest configured SHA_CRYPT rounds value is '#{highest}', expected >= #{required_rounds}"
    end
  end
end
