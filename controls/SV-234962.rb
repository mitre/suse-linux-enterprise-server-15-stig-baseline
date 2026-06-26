control 'SV-234962' do
  title 'The SUSE operating system file integrity tool must be configured to protect the integrity of the audit tools.'
  desc 'Protecting the integrity of the tools used for auditing purposes is a critical step toward ensuring the integrity of audit information. Audit information includes all information (e.g., audit records, audit settings, and audit reports) needed to successfully audit information system activity.

Audit tools include but are not limited to vendor-provided and open-source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

It is not uncommon for attackers to replace the audit tools or inject code into the existing tools to provide the capability to hide or erase system activity from the audit logs.

To address this risk, audit tools must be cryptographically signed to provide the capability to identify when the audit tools have been modified, manipulated, or replaced. An example is a checksum hash of the file or files.'
  desc 'check', 'Verify that the SUSE operating system file integrity tool is configured to protect the integrity of the audit tools.

Check that AIDE is properly configured to protect the integrity of the audit tools by running the following command:

> sudo grep /usr/sbin/au /etc/aide.conf

/usr/sbin/auditctl p+i+n+u+g+s+b+acl+selinux+xattrs+sha512
/usr/sbin/auditd p+i+n+u+g+s+b+acl+selinux+xattrs+sha512
/usr/sbin/ausearch p+i+n+u+g+s+b+acl+selinux+xattrs+sha512
/usr/sbin/aureport p+i+n+u+g+s+b+acl+selinux+xattrs+sha512
/usr/sbin/autrace p+i+n+u+g+s+b+acl+selinux+xattrs+sha512
/usr/sbin/audispd p+i+n+u+g+s+b+acl+selinux+xattrs+sha512
/usr/sbin/augenrules p+i+n+u+g+s+b+acl+selinux+xattrs+sha512

If AIDE is properly configured to protect the integrity of the audit tools, all lines listed above will be returned from the command. 

If one or more lines are missing, or is commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system file integrity tool to protect the integrity of the audit tools.

Add or update the following lines to "/etc/aide.conf" to protect the integrity of the audit tools:

# audit tools
/usr/sbin/auditctl p+i+n+u+g+s+b+acl+selinux+xattrs+sha512
/usr/sbin/auditd p+i+n+u+g+s+b+acl+selinux+xattrs+sha512
/usr/sbin/ausearch p+i+n+u+g+s+b+acl+selinux+xattrs+sha512
/usr/sbin/aureport p+i+n+u+g+s+b+acl+selinux+xattrs+sha512
/usr/sbin/autrace p+i+n+u+g+s+b+acl+selinux+xattrs+sha512
/usr/sbin/audispd p+i+n+u+g+s+b+acl+selinux+xattrs+sha512
/usr/sbin/augenrules p+i+n+u+g+s+b+acl+selinux+xattrs+sha512'
  impact 0.5
  tag check_id: 'C-38150r619155_chk'
  tag severity: 'medium'
  tag gid: 'V-234962'
  tag rid: 'SV-234962r991567_rule'
  tag stig_id: 'SLES-15-030630'
  tag gtitle: 'SRG-OS-000278-GPOS-00108'
  tag fix_id: 'F-38113r619156_fix'
  tag 'documentable'
  tag cci: ['CCI-001496']
  tag nist: ['AU-9 (3)']

  audit_tools = %w[
    /usr/sbin/auditctl
    /usr/sbin/auditd
    /usr/sbin/ausearch
    /usr/sbin/aureport
    /usr/sbin/autrace
    /usr/sbin/audispd
    /usr/sbin/augenrules
  ]
  # SLES uses AppArmor, so the SELinux attribute shown in the STIG's example rule
  # is intentionally omitted; the remaining attributes assert strong integrity coverage.
  required_attributes = %w[p i n u g s b acl xattrs sha512]

  if input('file_integrity_tool') == 'aide'
    audit_tools.each do |tool|
      describe "AIDE rule protecting audit tool #{tool}" do
        subject { aide_conf.where { selection_line == tool } }
        it { should exist }
        required_attributes.each do |attr|
          its('rules.flatten') { should include attr }
        end
      end
    end
  else
    describe "File integrity tool '#{input('file_integrity_tool')}'" do
      skip "Manually verify #{input('file_integrity_tool')} is configured to protect the integrity of the audit tools."
    end
  end
end
