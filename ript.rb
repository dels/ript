#!/usr/bin/env ruby

require_relative "./src/ript"

if __FILE__ == $0
  begin
    fw = Iptables.new ARGV[0]
  rescue Exception=>e
    puts "#{ e.message } - (#{ e.class })" << "\n" << (e.backtrace or []).join("\n")
  end
  puts fw.to_s
end


