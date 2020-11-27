# Base class for Cisco IOS devices used for sharing methods with other resources
class CiscoIOSBase < Inspec.resource(1)
  name 'cisco_ios_base'

  def run_ios_command(cmd)
    result = inspec.backend.run_command(cmd)

    if result.stderr =~ /Invalid input detected/
      err = "Command: `#{cmd}` failed, enable password correct? Bad command?"
    elsif !result.stderr.empty?
      err = result.stderr
    end
    raise Inspec::Exceptions::ResourceSkipped, err if err

    result.stdout
  end
end
