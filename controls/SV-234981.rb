control 'SV-234981' do
  title 'The SUSE operating system must not disable syscall auditing.'
  desc 'By default, the SUSE operating system includes the "-a task,never" audit rule as a default. This rule suppresses syscall auditing for all tasks started with this rule in effect. Because the audit daemon processes the "audit.rules" file from the top down, this rule supersedes all other defined syscall rules; therefore no syscall auditing can take place on the operating system.'
  desc 'check', 'Verify syscall auditing has not been disabled:

> auditctl -l | grep -i "a task,never"

If any results are returned, this is a finding.

Verify the default rule "-a task,never" is not statically defined :

> grep -rv "^#" /etc/audit/rules.d/ | grep -i "a task,never"

If any results are returned, this is a finding.'
  desc 'fix', 'Remove the "-a task,never" rule from the /etc/audit/rules.d/audit.rules file.

The audit daemon must be restarted for the changes to take effect.

> sudo systemctl restart auditd.service'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-234981'
  tag rid: 'SV-234981r991589_rule'
  tag stig_id: 'SLES-15-030820'
  tag fix_id: 'F-38132r619213_fix'
  tag cci: ['CCI-000366']
  tag legacy: []
  tag nist: ['CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  # A "task,never" rule disables syscall auditing; it must be absent both at runtime and in the static rules.
  loaded = command('auditctl -l').stdout.lines.grep(/task,never/i).map(&:strip)
  static = command("grep -rv '^#' /etc/audit/rules.d/ | grep -i 'task,never'").stdout.strip.split("\n").reject(&:empty?)

  describe 'Loaded audit rules (auditctl -l)' do
    it 'must not disable syscall auditing with a "task,never" rule' do
      expect(loaded).to be_empty, "Disabling rules loaded:\n\t- #{loaded.join("\n\t- ")}"
    end
  end

  describe 'Static audit rules in /etc/audit/rules.d' do
    it 'must not statically define a "task,never" rule' do
      expect(static).to be_empty, "Disabling rules in rules.d:\n\t- #{static.join("\n\t- ")}"
    end
  end
end
