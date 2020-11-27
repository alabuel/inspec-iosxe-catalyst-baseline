class CiscoIOSCommand < CiscoIOSBase
  name 'cisco_ios_command'

  desc 'Verifies the ouptut of a command on Cisco IOS devices'

  example <<-EXP
    describe cisco_ios_command('show running-config') do
      its('output') { should match /aaa new-model/ }
    end
  EXP

  def initialize(cmd)
    @command = cmd
  end

  def to_s
    "Cisco IOS Command '#{@command}'"
  end

  def output
    run_ios_command(@command)
  end
  alias stdout :output
end
