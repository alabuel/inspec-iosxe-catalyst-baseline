# -----------------------------------------------------------
# Variable assignment
# -----------------------------------------------------------

BANNER = attribute('BANNER', value: ['WARNING: Use of this System is restricted to authorised users only. User activity may be monitored and/or recorded. Anyone using this System expressly consents to such monitoring and/or recording. If possible criminal activity is detected, these records, along with certain personal information, may be provided to law enforcement officials.'])
SSH_AUTH_TIMEOUT = attribute('SSH_AUTH_TIMEOUT', value: 900)
SSH_AUTH_RETRIES = attribute('SSH_AUTH_RETRIES', value: 3)
LOGGING_BUFFER = attribute('LOGGING_BUFFER', value: 64000)
NAMED_ACCOUNTS = attribute('NAMED_ACCOUNTS', value: [])
NA_BASELINE_SETTINGS = attribute('NA_BASELINE_SETTINGS', value: ['4.1.1','4.1.2','4.1.3','4.1.4','4.4.1'])

LAYER3_FUNCTION = !(cisco_ios_running_config(includes: 'no switchport').lines).empty?
INTERNET_FACING = !(cisco_ios_running_config(includes: 'ip nat').lines).empty?

# -----------------------------------------------------------
# 4.1 Password Management
# -----------------------------------------------------------

control '4.1.1 Minimum Password Length' do
  title 'Minimum Password Length'
  desc '
    >=12 characters (normal user) 
    >=16 characters (privileged user)
    Minimum password length shall be enforced by operation process
  '

  impact 0
  
  describe '4.1.1 Minimum Password Length' do
    skip 'Will manually enter password with 16 char length'
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.1.1' }
end

control '4.1.2 Password Complexity' do
  title 'Password Complexity'
  desc '
    Enforce passwords contain characters from at least two of the following four categories:
    i. Upper case (A through Z);
    ii. Lower case (a through z);
    iii. Digits (0-9);
    iv. Special Characters (!, $, #, %, etc.);
    Ensure passwords are not displayed in clear.
    Password complexity shall be enforced by operation process
  '

  impact 0
  
  describe '4.1.2 Password Complexity' do
    skip 'Will manually ensure during password change'
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.1.2' }
end

control '4.1.3 Password History' do
  title 'Password History'
  desc '
    >=3 passwords remembered
    This setting will be enforced manually by the personnel during the password change.
    Password not displayed in clear  
  '

  impact 0
  
  describe '4.1.3 Password History' do
    skip 'Will manually set different password during password change'
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.1.3' }
end

control '4.1.4 Password Expiry' do
  title 'Password Expiry'
  desc '
    1 year
    Password shall be changed manually by operation process  
  '

  impact 0
  
  describe '4.1.4 Password Expiry' do
    skip 'No automated expiry. Will change password annually based on process'
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.1.4' }
end

control '4.1.5 Session Timeout' do
  title 'Session Timeout'
  desc '<=15 mins. This is the current IM8 requirement'

  impact 1.0
  
  describe cisco_ios_running_config(section: 'line vty 0 4') do
    it { should have_line /session-timeout (10|\d) \d{1,2}/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.1.5' }
end

control '4.1.6 Password encrypted in transit' do
  title 'Password encrypted in transit'
  desc 'Use SSH and SFTP to encrypt password in transit'

  impact 1.0
  
  describe.one do
    describe cisco_ios_running_config(section: 'line vty') do
      it { should have_line /transport input ssh/ }
    end
    describe cisco_ios_running_config(section: 'line vty') do
      it { should have_line /transport input sftp/ }
    end
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.1.6' }
end

control '4.1.7 Password must be changed upon first login' do
  title 'Password must be changed upon first login'
  desc 'Password shall be changed upon first login manually by the user'

  impact 0
  
  describe '4.1.7 Password must be changed upon first login' do
    skip 'Password will be changed manually'
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.1.7' }
end

control '4.1.8 Password must be the same as user ID' do
  title 'Password must be the same as user ID'
  desc 'Password set by the user shall not be the same as the user ID'

  impact 1.0
  
  cisco_line = (cisco_ios_running_config(includes: 'username').lines)
  cisco_line.each do |line|
    cline = line.split(' ')
    username_line = {}
    username_line['username'] = cline[1]
    username_line['password'] = cline[4]
    
    describe json({content: username_line.to_json}) do
      its('password') { should_not match username_line['username'] }
    end
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.1.8' }
end

# -----------------------------------------------------------
# 4.2 Account Management
# -----------------------------------------------------------

control '4.2.1 Default Accounts' do
  title 'Default Accounts'
  desc 'Rename default admin accounts and change password. At least one local administrator account is needed'

  impact 1.0

  describe cisco_ios_running_config(includes: 'username') do
    it { should_not have_line /cisco/ }
    it { should_not be_empty }
  end
  
  only_if { !NA_BASELINE_SETTINGS.include? '4.2.1' }
end

control '4.2.2 Named Accounts' do
  title 'Named Accounts'
  desc 'Named accounts to be created and used where possible'

  impact 1.0

  NAMED_ACCOUNTS.each do |nacct|
    describe cisco_ios_running_config(includes: 'username') do
      it { should have_line /#{nacct}/ }
    end
  end
  describe cisco_ios_running_config(includes: 'username') do
    it { should_not be_empty }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.2.2' }
end

# -----------------------------------------------------------
# 4.3 Authentication Mechanisms
# -----------------------------------------------------------

control '4.3.1 Approved authentication mechanisms' do
  title 'Default Accounts'
  desc 'Use only approved authentication mechanisms, e.g. Kerberos, RADIUS, TACACS+, SAML, LDAP or LDAPS.  Configure TACACS+ to authorised TACACS servers'

  impact 1.0

  describe cisco_ios_running_config do
    it { should have_line /^aaa group server tacacs.*/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.3.1' }
end

# -----------------------------------------------------------
# 4.4 Access Methods
# -----------------------------------------------------------

control '4.4.1 Approved access methods – Enable strong TLS' do
  title 'Approved access methods – Enable strong TLS'
  desc 'Use TLS 1.2 and above.  Disable TLS 1.0, TLS 1.1, SSLvx'

  impact 0

  describe '4.4.1 Approved access methods – Enable strong TLS' do
    skip 'This is a tender specs requirement'
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.4.1' }
end

control '4.4.2 Approved access methods – Secure Login' do
  title 'Approved access methods – Secure Login'
  desc 'Use SSHv2. Disable SSHv1, plain Telnet'

  impact 1.0

  describe cisco_ios_running_config do
    it { should have_line /^ip ssh version 2.*/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.4.2' }
end

control '4.4.3 Approved Access Methods – Use Strong Cipher' do
  title 'Approved Access Methods – Use Strong Cipher'
  desc 'Use approved strong cipher, indicate strength or setting. Use AES-256 and above, RSA-2048 and above, SHA-2 (SHA-256, SHA-384, SHA-512); or SHA3.  ECDHE, HMAC-128 and above'

  impact 1.0

  describe.one do
    describe cisco_ios_running_config do
      it { should have_line /^ip ssh server algorithm encryption aes256-ctr.*/ }
    end
    describe cisco_ios_running_config do
      it { should have_line /^ip ssh server algorithm mac hmac-sha2-256.*/ }
    end
    describe cisco_ios_running_config do
      it { should have_line /^ip ssh client algorithm encryption aes256-ctr.*/ }
    end
    describe cisco_ios_running_config do
      it { should have_line /^ip ssh client algorithm mac hmac-sha2-256.*/ }
    end
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.4.3' }
end

# -----------------------------------------------------------
# 4.5 Ports, Protocols, and Services
# -----------------------------------------------------------

control '4.5.1 Disable vulnerable services' do
  title 'Disable vulnerable services'
  desc 'All vulnerable services are disabled'

  impact 0

  describe '4.5.1 Disable vulnerable services' do
    skip 'Any vulnerabilities that is published by Cisco and is applicable will be remediated'
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.5.1' }
end

control '4.5.2 Disable unused ports' do
  title 'Disable vulnerable services'
  desc 'All unused ports are disabled'

  impact 1.0

  describe cisco_ios_running_config(section: 'aux 0') do
    it { should have_line /transport input none.*/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.5.2' }
end

control '4.5.3 Use only secure network protocols for administration' do
  title 'Use only secure network protocols for administration'
  desc 'All unused ports are disabled. Administration of Cisco ASR is via SSHv2'

  impact 1.0

  describe cisco_ios_running_config do
    it { should have_line /^ip ssh version 2.*/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.5.3' }
end

# -----------------------------------------------------------
# 4.6 System Settings
# -----------------------------------------------------------

control '4.6.1 System Time Sync' do
  title 'Set to CCIS-defined NTP settings'
  desc 'Configure NTP to authorized NTP servers'

  impact 1.0

  describe cisco_ios_running_config do
    it { should have_line /^ntp server.*$/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.6.1' }
end

# -----------------------------------------------------------
# 4.7 Audit, Logging and Monitoring
# -----------------------------------------------------------

control '4.7.1 Enable auditing' do
  title 'Enable security audit setting for security events including authentication and privileged activities, such as configuration changes performed'
  desc 'Enable security audit settings'

  impact 1.0

  describe cisco_ios_running_config(section: 'archive') do
    it { should have_line /^log config.*$/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.7.1' }
end

control '4.7.2 Set syslog host' do
  title 'Send to syslog host'
  desc 'Configure to authorised syslog server'

  impact 1.0

  describe cisco_ios_running_config do
    it { should have_line /^logging host\s+\d+\.\d+\.\d+\.\d+.*$/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.7.2' }
end

control '4.7.3 SNMP' do
  title 'Use SNMPv3 (preferred), SNMPv2c and change default community string. Assign read-only access (preferred)'
  desc 'Follow minimum password length and complexity for community string'

  impact 1.0

  # Use SNMPv3 (preferred)
  describe cisco_ios_snmp_groups.where { security_model !~ /v3/ } do
    its('entries') { should_not be_empty }
  end

  # Assign read-only access (preferred)
  describe cisco_ios_snmp_communities.where { storage_type == 'RW' } do
    its('entries') { should be_empty }
  end

  # Change default community strings
  describe cisco_ios_snmp_communities.where { name =~ /[Pp]rivate/ } do
    its('entries') { should be_empty }
  end
  describe cisco_ios_snmp_communities.where { name =~ /[Pp]ublic/ } do
    its('entries') { should be_empty }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.7.2' }
end

# -----------------------------------------------------------
# 4.8 PKI/Certificates
# -----------------------------------------------------------

control '4.8.1 PKI/Certificates' do
  title 'Use only CCIS PKI or government-issued certificates'
  desc 'Applicable for Cisco IOS-XE that using IPsec tunnel with peers'

  impact 1.0

  tunnel = cisco_ios_running_config(includes: 'tunnel')
  if !tunnel.empty?
    describe cisco_ios_running_config(includes: 'crypto pki certificate') do
      it { should_not be_empty}
    end
  else
    describe 'PKI/Certificates' do
      skip 'Applicable for Cisco IOS-XE that using IPsec tunnel with peers'
    end
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.8.1' }
end

# -----------------------------------------------------------
# 4.9 Patch Management
# -----------------------------------------------------------

control '4.9.1 Patch Management' do
  title 'Apply latest security patches, including firmware patches. Ensure patch deployment follows patch cycle'
  desc 'Apply the security patches manually through operation process'

  impact 0

  describe '4.9.1 Patch Management' do
    skip 'Apply the security patches manually through operation process'
  end

  only_if { !NA_BASELINE_SETTINGS.include? '4.9.1' }
end

# -----------------------------------------------------------
# 5.1 Management Plane
# -----------------------------------------------------------

control '5.1.1 Ensure local authentication max failed attempts is set to less than or equal to 10' do
  title '<=10 failed logins'
  desc 'This is the current IM8 requirement'

  impact 1.0

  describe cisco_ios_running_config(includes: 'aaa local authentication attempts') do
    it { should match /max-fail 10/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.1.1' }
end

control '5.1.2 Ensure local username and password is set' do
  title 'Set a local username and password'
  desc 'As per recommended settings'

  impact 1.0

  describe cisco_ios_running_config(includes: 'username') do
    it { should_not have_line /cisco/ }
    it { should_not be_empty }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.1.2' }
end

control '5.1.2 Ensure local username and password is set' do
  title 'Set a local username and password'
  desc 'As per recommended settings'

  impact 1.0

  describe cisco_ios_running_config(includes: 'username') do
    it { should_not have_line /cisco/ }
    it { should_not be_empty }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.1.2' }
end

control '5.1.3 Enable AAA Service' do
  title 'Globally enable authentication, authorization and accounting (AAA) using new-model command'
  desc 'As per recommended settings'

  impact 1.0
  tag cis: '1.1.1'

  describe cisco_ios_running_config do
    it { should have_line /^aaa new-model$/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.1.3' }
end

control '5.1.4 AAA Authentication for Enable Mode' do
  title 'Configure AAA authentication method(s) for enable authentication'
  desc 'As per recommended settings'

  impact 1.0
  tag cis: '1.1.3'

  describe cisco_ios_running_config do
    it { should have_line /^aaa authentication enable.*/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.1.4' }
end

control '5.1.5 AAA Authentication for Local Console 0' do
  title 'Configure management lines of console interface to require login using the default or a named AAA authentication list'
  desc 'As per recommended settings'

  impact 1.0
  tag cis: '1.1.4'

  describe cisco_ios_running_config(section: 'line con 0') do
    it { should have_line /login authentication/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.1.5' }
end

control '5.1.6 AAA Authentication for line VTY' do
  title 'Configure management lines of vty 0 to 4 to require login using the default or a named AAA authentication list'
  desc 'As per recommended settings'

  impact 1.0
  tag cis: '1.1.6'

  describe cisco_ios_running_config(section: 'line vty 0 4') do
    it { should have_line /login authentication/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.1.6' }
end

control '5.1.7 Require AAA Accounting Commands' do
  title 'Configure AAA accounting for commands'
  desc 'As per recommended settings'

  impact 1.0
  tag cis: '1.1.7'

  describe cisco_ios_running_config do
    it { should have_line /^aaa accounting commands.*/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.1.7' }
end

control '5.1.8 Require AAA Accounting Connection' do
  title 'Configure AAA accounting for connections'
  desc 'As per recommended settings'

  impact 1.0
  tag cis: '1.1.8'

  describe cisco_ios_running_config do
    it { should have_line /^aaa accounting connection.*/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.1.8' }
end

control '5.1.9 Require AAA Accounting Exec' do
  title 'Configure AAA accounting for exec'
  desc 'As per recommended settings'

  impact 1.0
  tag cis: '1.1.9'

  describe cisco_ios_running_config do
    it { should have_line /^aaa accounting exec.*/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.1.9' }
end

control '5.1.10 Require AAA Accounting Network' do
  title 'Configure AAA accounting for network'
  desc 'As per recommended settings'

  impact 1.0
  tag cis: '1.1.10'

  describe cisco_ios_running_config do
    it { should have_line /^aaa accounting network.*/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.1.10' }
end

control '5.1.11 Require AAA Accounting System' do
  title 'Configure AAA accounting for system'
  desc 'As per recommended settings'

  impact 1.0
  tag cis: '1.1.11'

  describe cisco_ios_running_config do
    it { should have_line /^aaa accounting system.*/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.1.11' }
end

# -----------------------------------------------------------
# 5.2 Access Rules
# -----------------------------------------------------------

control '5.2.1 VTY Transport SSH' do
  title 'Apply transport SSH on all management lines of VTY 0 - 4'
  desc 'This is the current IM8 requirement'

  impact 1.0
  tag cis: '1.2.2'

  describe cisco_ios_running_config(section: 'line vty 0 4') do
    it { should have_line /transport input ssh/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.2.1' }
end

control '5.2.2 Forbid Auxiliary Port' do
  title 'Disable the EXEC process on the auxiliary port'
  desc 'This is the current IM8 requirement'

  impact 1.0
  tag cis: '1.2.3'

  describe.one do
    describe cisco_ios_running_config(section: 'line aux') do
      it { should be_empty }
    end
    describe cisco_ios_running_config(section: 'line aux') do
      it { should have_line /no exec/ }
    end
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.2.2' }
end

control '5.2.3 VTY ACL' do
  title 'Configure the VTY ACL that will be used to restrict management access to the device and allow only authorized management servers'
  desc 'This is the current IM8 requirement'

  impact 1.0
  tag cis: '1.2.4'

  describe cisco_ios_running_config(section: 'line vty') do
    it { should have_line /access-class [\d\w]+ in/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.2.3' }
end

control '5.2.4 VTY Access Control' do
  title 'Configure remote management access control restrictions for all VTY lines'
  desc 'This is the current IM8 requirement'

  impact 1.0
  tag cis: '1.2.5'

  describe cisco_ios_running_config(section: 'line vty') do
    it { should have_line /access-class [\d\w]+ in/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.2.4' }
end

control '5.2.5 Timeout for line vty' do
  title 'Configure device timeout to disconnect sessions after 15 minutes idle time'
  desc 'This is the current IM8 requirement'

  impact 1.0
  tag cis: '1.2.8'

  describe cisco_ios_running_config(section: 'line vty') do
    it { should have_line /exec-timeout (15|\d) \d{1,2}/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.2.5' }
end

# -----------------------------------------------------------
# 5.3 Banner Rules
# -----------------------------------------------------------

control '5.3.1 Ensure EXEC Banner is set' do
  title 'Apply transport SSH on all management lines of VTY 0 - 4'
  desc 'This is the current IM8 requirement'

  impact 1.0
  tag cis: '1.3.1'

  describe cisco_ios_running_config(section: 'banner exec') do
    its('lines') { should cmp /#{BANNER}/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.3.1' }
end

control '5.3.2 Ensure Login Banner' do
  title 'Configure banner'
  desc 'Use CCIS-defined banner where supported'

  impact 1.0
  tag cis: '1.3.2'

  describe cisco_ios_running_config(section: 'banner login') do
    its('lines') { should cmp /#{BANNER}/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.3.2' }
end

control '5.3.3 MOTD Banner' do
  title 'Configure the message of the day (MOTD) banner'
  desc 'As per recommended settings'

  impact 1.0
  tag cis: '1.3.3'

  describe cisco_ios_running_config(section: 'banner motd') do
    its('lines') { should cmp /#{BANNER}/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.3.3' }
end

# -----------------------------------------------------------
# 5.4 Password Rules
# -----------------------------------------------------------

control '5.4.1 Enable Secret' do
  title 'Enable secret password is defined using strong encryption to protect access to privileged EXEC mode (enable mode) which is used to configure the device'
  desc 'As per recommended settings'

  impact 1.0
  tag cis: '1.4.1'

  describe cisco_ios_running_config do
    it { should have_line /^enable secret.*$/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.4.1' }
end

control '5.4.2 Password Encryption Service' do
  title 'Enable password encryption service'
  desc 'This service ensures passwords are rendered as encrypted strings preventing an attacker from easily determining the configured value. When not enabled, many of the device’s passwords will be rendered in plain text in the configuration file'

  impact 1.0
  tag cis: '1.4.2'

  describe cisco_ios_running_config do
    it { should have_line /^service password-encryption.*/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.4.2' }
end

control '5.4.3 Username secret for all local users' do
  title 'Username secret for all local users'
  desc 'The username secret command provides an additional layer of security over the username password'

  impact 1.0
  tag cis: '1.4.3'

  describe cisco_ios_running_config do
    it { should have_line /^username\s+\w+\s+privilege\s+\d+\s+secret.*$/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.4.3' }
end

# -----------------------------------------------------------
# 5.5 SNMP Rules
# -----------------------------------------------------------

control '5.5.1 Forbid SNMP server' do
  title 'If not in use, disable simple network management protocol (SNMP), read and write access'
  desc 'Only SNMP read-only access will be enabled as required'

  impact 1.0
  tag cis: '1.5.1'

  describe cisco_ios_snmp_communities.where { name =~ /.*/ } do
    its('entries') { should_not be_empty }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.5.1' }
end

control '5.5.2 Forbid SNMP Community String private' do
  title 'Disable the default SNMP community string ‘private’. The default community string "private" is well known. Using easy to guess, well known community string poses a threat that an attacker can effortlessly gain unauthorized access to the device'
  desc 'Configuration does not contain default simple network management protocol (SNMP) community strings. The configuration cannot include snmp-server community commands with prohibited community strings'

  impact 1.0
  tag cis: '1.5.2'

  describe cisco_ios_snmp_communities.where { name =~ /[Pp]rivate/ } do
    its('entries') { should be_empty }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.5.2' }
end

control '5.5.3 Forbid SNMP Community String public' do
  title 'Disable the default SNMP community string “public”. The default community string "public" is well known. Using easy to guess, well known community string poses a threat that an attacker can effortlessly gain unauthorized access to the device'
  desc 'Configuration does not contain default simple network management protocol (SNMP) community strings. The configuration cannot include snmp-server community commands with prohibited community strings'

  impact 1.0
  tag cis: '1.5.3'

  describe cisco_ios_snmp_communities.where { name =~ /[Pp]ublic/ } do
    its('entries') { should be_empty }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.5.3' }
end

control '5.5.4 Forbid SNMP Write Access' do
  title 'Disable SNMP write access'
  desc 'The device does not allow simple network management protocol (SNMP) write access'

  impact 1.0
  tag cis: '1.5.4'

  describe cisco_ios_snmp_communities.where { storage_type == 'RW' } do
    its('entries') { should be_empty }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.5.4' }
end

control '5.5.5 Defines a SNMP ACL' do
  title 'Configure SNMP ACL for restricting access to the device from authorized management stations segmented in a trusted management zone'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '1.5.4'

  describe cisco_ios_snmp_communities.where { access_list =~ /.*/ } do
    its('entries.length') { should be >= 1 }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.5.5' }
end

control '5.5.6 SNMP Trap Server When Using SNMP' do
  title 'Configure authorized SNMP trap community string and restrict sending messages to authorized management systems'
  desc 'The device is configured to submit SNMP traps only to authorized systems required to manage the device'

  impact 1.0
  tag cis: '1.5.7'

  describe cisco_ios_snmp do
    its('hosts') { should_not be_empty }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.5.6' }
end

control '5.5.7 Allow SNMP Traps on, when SNMP Trap server defined' do
  title 'Ensure SNMP traps are enable'
  desc 'The device is configured to send SNMP traps'

  impact 1.0
  tag cis: '1.5.8'

  describe cisco_ios_running_config do
    it { should have_line /snmp-server enable traps/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.5.7' }
end

control '5.5.8 Group for SNMPv3 Access' do
  title 'Create SNMPv3 group (Do not allow plaintext SNMPv3 access)'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '1.5.8'

  describe cisco_ios_snmp_groups.where { security_model !~ /v3/ } do
    its('entries') { should_not be_empty }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.5.8' }
end

control '5.5.9 AES256 or Better Encryption for SNMPv3 user' do
  title 'Create SNMPv3 user with authentication and encryption options.AES256 is the minimum strength encryption method that should be deployed'
  desc 'Do not allow plaintext SNMPv3 access'

  impact 1.0
  tag cis: '1.5.8'

  describe cisco_ios_snmp_users.where { privacy_protocol == 'AES256' } do
    its('entries') { should_not be_empty }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '5.5.9' }
end

# -----------------------------------------------------------
# 6.1 Global Service Rules
# -----------------------------------------------------------

control '6.1.1 Configure the Host Name' do
  title 'Configure an appropriate host name for the switch. The host name is a prerequisite for setting up SSH'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '2.1.1.1.1'

  describe cisco_ios_running_config do
    it { should have_line /^hostname .*$/ }
  end
  describe cisco_ios_running_config do
    it { should_not have_line /hostname [Ss]witch/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.1.1' }
end

control '6.1.2 Configure the Domain Name' do
  title 'Configure an appropriate domain name for the switch'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '2.1.1.1.2'

  describe cisco_ios_running_config do
    it { should have_line /^ip domain name .*$/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.1.2' }
end

control '6.1.3 Generate the RSA Key Pair' do
  title 'Generate an RSA key pair for the switch. An RSA key pair is a prerequisite for setting up SSH and should be at least 2048 bits'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '2.1.1.1.3'

  describe cisco_ios_running_config(includes: 'crypto key') do
    it { should_not be_empty }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.1.3' }
end

control '6.1.4 Configure the SSH Timeout' do
  title 'Configure device SSH timeout to disconnect sessions after 15 minutes idle time'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '2.1.1.1.4'

  describe cisco_ios_file_output('show_ip_ssh', includes: 'timeout') do
    it { should have_line /^Authentication timeout: #{SSH_AUTH_TIMEOUT} secs;.*$/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.1.4' }
end

control '6.1.5 Limit the number of SSH Authentication Retries' do
  title 'Device is configured to limit the number of SSH authentication attempts. Retry attempts minimally must be set 3 attempts'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '2.1.1.1.5'

  describe cisco_ios_file_output('show_ip_ssh', includes: 'retries') do
    it { should have_line /^.*Authentication retries: #{SSH_AUTH_RETRIES}/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.1.5' }
end

control '6.1.6 Ensure SSH version 2 is enabled' do
  title 'Configure the switch to use SSH version 2'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '2.1.1.2'

  describe cisco_ios_running_config do
    it { should have_line 'ip ssh version 2' }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.1.6' }
end

control '6.1.7 Forbid CDP Run Globally' do
  title 'Disable Cisco Discovery Protocol (CDP) service at device level'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '2.1.2'

  describe cisco_ios_file_output('show_cdp') do
    it { should have_line /^.*CDP is not enabled$/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.1.7' }
end

control '6.1.8 Forbid IP BOOTP Server' do
  title 'Disable the bootp server'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '2.1.3'

  describe cisco_ios_running_config do
    it { should have_line 'no ip bootp server' }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.1.8' }
end

control '6.1.9 Forbid DHCP Server Service' do
  title 'Disable the DHCP server'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '2.1.4'

  describe cisco_ios_running_config do
    it { should have_line 'no service dhcp' }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.1.9' }
end

control '6.1.10 Forbid Identification Server' do
  title 'Disable the Ident server'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '2.1.5'

  describe cisco_ios_running_config do
    it { should_not have_line /^ip identd$/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.1.10' }
end

control '6.1.11 Require TCP keepalives-in Service' do
  title 'Enable TCP keepalives-in service to kill sessions where the remote side has died'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '2.1.6'

  describe cisco_ios_running_config do
    it { should have_line 'service tcp-keepalives-in' }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.1.11' }
end

control '6.1.12 Require TCP keepalives-out Service' do
  title 'Enable TCP keepalives-out service to kill sessions where the remote side has died'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '2.1.7'

  describe cisco_ios_running_config do
    it { should have_line 'service tcp-keepalives-out' }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.1.12' }
end

control '6.1.13 Forbid PAD Service' do
  title 'Disable the PAD service'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '2.1.8'

  describe cisco_ios_running_config do
    it { should have_line 'no service pad' }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.1.13' }
end

# -----------------------------------------------------------
# 6.2 Logging Rules
# -----------------------------------------------------------

control '6.2.1 Logging Buffer' do
  title 'Configure buffered logging (with minimum size). Recommended size is 64000'
  desc 'Buffered logging (with minimum size) is configured to enable logging to internal device memory buffer'

  impact 1.0
  tag cis: '2.2.2'

  describe cisco_ios_running_config do
    it { should have_line /^logging buffered #{LOGGING_BUFFER}$/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.2.1' }
end

control '6.2.2 Logging to Device Console' do
  title 'Configure console logging level with recommended level by Syslog system'
  desc 'Logging to device console is enabled and limited to a rational severity level to avoid impacting system performance and management'

  impact 1.0
  tag cis: '2.2.3'

  describe cisco_ios_running_config do
    it { should have_line /^logging console (critical|informational)$/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.2.2' }
end

control '6.2.3 Logging Trap Severity Level' do
  title 'Configure SNMP trap and syslog logging with recommended level by Syslog system'
  desc 'Simple network management protocol (SNMP) trap and Syslog are set to required level'

  impact 1.0
  tag cis: '2.2.5'

  describe cisco_ios_file_output('show_log', includes: 'Trap logging') do
    it { should have_line /^.*Trap logging:\s+level\s(informational|debugging)/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.2.3' }
end

control '6.2.4 Service Timestamps for Debug and Log Messages' do
  title 'Configure debug messages to include timestamps'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '2.2.6'

  describe cisco_ios_running_config do
    it { should have_line /^service timestamps debug datetime.*$/ }
  end
  describe cisco_ios_running_config do
    it { should have_line /^service timestamps log datetime.*$/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.2.4' }
end

control '6.2.5 Binding Logging Service to Loopback Interface' do
  title 'Bind logging to the loopback interface'
  desc 'Logging messages are bound to the loopback interface'

  impact 1.0
  tag cis: '2.2.7'

  describe cisco_ios_running_config do
    it { should have_line /^logging source-interface.*$/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.2.5' }
end

# -----------------------------------------------------------
# 6.3 Loopback Rules
# -----------------------------------------------------------

control '6.3.1 Require Loopback Interface' do
  title 'Define and configure one loopback interface'
  desc 'Only applicable for Catalyst switch that running as Layer 3 function'

  impact 1.0
  tag cis: '2.4.1'

  describe cisco_ios_file_output('show_ip_interface_brief', includes: 'Loopback') do
    it { should_not be_empty }
  end

  only_if { LAYER3_FUNCTION == true }
  only_if { !NA_BASELINE_SETTINGS.include? '6.3.1' }
end

control '6.3.2 Require Binding AAA Service to an Interface' do
  title 'Bind AAA services to the physical interface'
  desc 'Authentication, authorization and accounting (AAA) services are bound to the Physical interface'

  impact 1.0
  tag cis: '2.4.2'

  describe cisco_ios_running_config do
    it { should have_line /tacacs source.*/ }
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.3.2' }
end

control '6.3.3 Require Binding the NTP Service to Loopback Interface' do
  title 'Bind the NTP service to the loopback interface'
  desc 'Only applicable for Catalyst switch that running as Layer 3 function'

  impact 1.0
  tag cis: '2.4.3'

  describe cisco_ios_running_config do
    it { should have_line /^ntp source.*/ }
  end

  only_if { LAYER3_FUNCTION == true }
  only_if { !NA_BASELINE_SETTINGS.include? '6.3.3' }
end

control '6.3.4 Require Binding TFTP Client Service to Management Interface' do
  title 'Bind the TFTP service to the Management interface'
  desc 'Not Applicable. Only SCP/SFTP secure protocol is used in the internal network'

  impact 0

  describe '6.3.4 Require Binding TFTP Client Service to Management Interface' do
    skip 'Not Applicable. Only SCP/SFTP secure protocol is used in the internal network'
  end

  only_if { !NA_BASELINE_SETTINGS.include? '6.3.4' }
end

# -----------------------------------------------------------
# 6.4 Control Plane Rules
# -----------------------------------------------------------

control '6.4.1 Control plane policing' do
  title 'The CPP feature protects the control plane of Cisco IOS Software-based router or switch against many attacks, including reconnaissance and denial-of-service (DoS) attacks. In this manner, the control plane can maintain packet forwarding and protocol state despite an attack or heavy load on the router or switch'
  desc 'Only applicable the device which is Internet Facing Router and Internet Public IP connection is implemented'

  impact 1.0
  tag cis: '2.4.1'

  describe cisco_ios_file_output('show_policy_map_control_plane') do
    it { should have_line /Service-policy\s+input.*/ }
  end
  describe cisco_ios_file_output('show_ip_access_list') do
    it { should have_line /(COPP|cpp)/ }
  end

  only_if { INTERNET_FACING == true }
  only_if { !NA_BASELINE_SETTINGS.include? '6.4.1' }
end

# -----------------------------------------------------------
# 7.1 Routing Rules
# -----------------------------------------------------------

control '7.1.1 Forbid Directed Broadcast' do
  title 'Disable directed broadcast on each interface'
  desc 'Only applicable for Catalyst switches as running Layer 3 function'

  impact 1.0

  describe cisco_ios_file_output('show_ip_interface', includes: '[Dd]irected broadcast') do
    it { should_not have_line /enabled/ }
  end
  
  only_if { LAYER3_FUNCTION == true }
  only_if { !NA_BASELINE_SETTINGS.include? '7.1.1' }
end

control '7.1.2 ICMP Redirect Message' do
  title 'Disallowing all L3 interfaces from sending ICMP redirect messages is recommended'
  desc 'Only applicable for Catalyst switches as running Layer 3 function'

  impact 1.0

  describe cisco_ios_file_output('show_ip_interface', includes: 'ICMP redirects') do
    it { should_not have_line /always sent/ }
  end
  
  only_if { LAYER3_FUNCTION == true }
  only_if { !NA_BASELINE_SETTINGS.include? '7.1.2' }
end

control '7.1.3 ICMP Unreachable Messages' do
  title 'Disallowing all L3 interfaces from sending ICMP unreachable messages for traffic filtered by ACL is recommended'
  desc 'Only applicable for Catalyst switches as running Layer 3 function'

  impact 1.0

  describe cisco_ios_file_output('show_ip_interface', includes: 'ICMP unreachables') do
    it { should_not have_line /always sent/ }
  end
  
  only_if { LAYER3_FUNCTION == true }
  only_if { !NA_BASELINE_SETTINGS.include? '7.1.3' }
end

control '7.1.4 Forbid IP source-route' do
  title 'Disable source routing'
  desc 'As per recommended setting'

  impact 1.0
  tag cis: '3.1.1'

  describe cisco_ios_running_config do
    it { should have_line /^no ip source-route$/ }
  end
  
  only_if { !NA_BASELINE_SETTINGS.include? '7.1.4' }
end

control '7.1.5 Forbid IP Proxy ARP' do
  title 'Disable proxy ARP on all interfaces'
  desc 'Only applicable for Catalyst switches as running Layer 3 function'

  impact 1.0
  tag cis: '3.1.2'

  describe cisco_ios_interfaces.where { proxy_arp_enabled? } do
    its('entries') { should be_empty }
  end
  
  only_if { LAYER3_FUNCTION == true }
  only_if { !NA_BASELINE_SETTINGS.include? '7.1.5' }
end

control '7.1.6 Forbid Tunnel Interfaces' do
  title 'Do not define any tunnel interfaces'
  desc 'Not applicable for Cisco Catalyst switches as there is no tunnel with peers'

  impact 1.0
  tag cis: '3.1.3'

  describe cisco_ios_file_output('show_ip_interface', includes: 'tunnel') do
    it { should be_empty }
  end
  describe '7.1.6 Forbid Tunnel Interfaces' do
    skip 'Not applicable for Cisco Catalyst switches as there is no tunnel with peers'
  end
  
  only_if { !NA_BASELINE_SETTINGS.include? '7.1.6' }
end

control '7.1.7 Enable Unicast Reverse-Path Forwarding (uRPF)' do
  title 'Configure unicast reverse-path forwarding (uRPF) on all external or high risk interfaces'
  desc 'Only applicable for Cisco Catalyst switches which running as Layer 3 function'

  impact 1.0
  tag cis: '3.1.3'

  describe cisco_ios_interfaces.where { ip_verify_source != 'reachable-via rx' } do
    its('entries') { should be_empty }
  end

  only_if { LAYER3_FUNCTION == true }
  only_if { !NA_BASELINE_SETTINGS.include? '7.1.7' }
end

control '7.1.8 Enable Unicast Reverse-Path Forwarding (uRPF)' do
  title 'Configure unicast reverse-path forwarding (uRPF) on all external or high risk interfaces'
  desc 'Only applicable for Cisco Catalyst switches which running as Layer 3 function'

  impact 1.0
  tag cis: '3.1.3'

  describe cisco_ios_interfaces.where { ip_verify_source != 'reachable-via rx' } do
    its('entries') { should be_empty }
  end

  only_if { LAYER3_FUNCTION == true }
  only_if { !NA_BASELINE_SETTINGS.include? '7.1.7' }
end

# -----------------------------------------------------------
# 7.2 IPv6 Configuration
# -----------------------------------------------------------

control '7.2.1 IPv6 Settings' do
  title 'Disable IPv6 Settings on required interfaces'
  desc 'As per recommended setting'

  impact 1.0

  describe cisco_ios_file_output('show_ipv6_interface') do
    it { should be_empty }
  end
  
  only_if { !NA_BASELINE_SETTINGS.include? '7.2.1' }
end

