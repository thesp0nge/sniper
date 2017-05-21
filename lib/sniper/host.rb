module Sniper
  class Host

    attr_reader :ip
    attr_reader :hostname
    attr_reader :os
    attr_reader :services

    def initialize(options={})
      # you can optimize this one with metaprogramming
      @ip       = options[:ip]
      @hostname = options[:hostname]
      @os       = options[:os]
      @services = []
    end

    def add_service(service)
      @services << service
    end
  end
end
