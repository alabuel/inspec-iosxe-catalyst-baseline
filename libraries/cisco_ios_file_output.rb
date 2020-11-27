class CiscoIOSFileOutput < CiscoIOSBase
  name 'cisco_ios_file_output'

  desc 'Verifies the contents of the file output on Cisco IOS devices'

  example <<-EXP
    describe cisco_ios_file_output do
      it { should have_line(/Authentication timeout: .*/) }
    end
  EXP

  attr_reader :content
  def initialize(filename, includes: '')
    @filename = filename
    if includes != ''
      @content = ''
      if File.exist?("output/#{filename}")
        File.open("output/#{filename}",'r') do |f|
          f.each_line do |line|
            if line =~ /#{includes}/
              @content += line.gsub(/\s+$/, '') + "\n"
            end
          end
        end
      end
    else
      @content = File.read("output/#{filename}")
    end
  end

  def to_s
    "Cisco IOS File Output (#{@filename})"
  end

  def lines
    @lines ||= parse_content(@content).split("\n")
  end

  def has_line?(line) # rubocop:disable PredicateName
    return lines.find { |l| l =~ line } ? true : false if line.is_a?(Regexp)
    lines.include?(line)
  end

  private

  def parse_content(content)
    exclamation_point_lines = /!.*\n/
    double_newlines = /\n\n/

    content.gsub(exclamation_point_lines, '')
           .gsub(double_newlines, "\n")
           .gsub(/\s+$/, '')
  end
end
