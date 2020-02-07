class Firewall
    def initialize(path)
        #0 is TCP_in, 1 is UDP_in, 2 is TCP_out, 3 is UDP_out
        @rules = Array.new(4) {Array.new(65536)}

        File.foreach(path) do |line|
            rule = line.strip.split(',')
            port = rule[2].split('-')
            ip_address = rule[3].split('-')

            #choose array to add rule in
            rules_index = 0
            if rule[0] === "inbound" 
                rules_index = 1 if rule[1] === "udp"
            else
                rules_index = rule[1] === "tcp" ? 2 : 3
            end

            #if range of ports
            if port.length() > 1 
                for i in port[0].to_i .. port[1].to_i
                    if @rules[rules_index][i].nil?
                        @rules[rules_index][i] = Hash.new
                    end
                    if ip_address.length() > 1
                        for j in ip_to_number(ip_address[0]) .. ip_to_number(ip_address[1])
                            @rules[rules_index][i][number_to_ip(j)] = true
                        end
                    else
                        @rules[rules_index][i][ip_address[0]] = true
                    end
                end
            #single port
            else
                #hash doesn't exist for this port yet
                if @rules[rules_index][port[0].to_i].nil?
                    @rules[rules_index][port[0].to_i] = Hash.new
                end
                #range of IPs
                if ip_address.length() > 1
                    for j in ip_to_number(ip_address[0]) .. ip_to_number(ip_address[1])
                        @rules[rules_index][port[0].to_i][number_to_ip(j)] = true
                    end
                #single IP
                else
                    @rules[rules_index][port[0].to_i][number_to_ip(ip_to_number(ip_address[0]))] = true
                end
            end
        end
    end


    def accept_packet(direction, protocol, port, ip_address)
        #choose array to check rule in
        rules_index = 0
        if direction === "inbound"
            rules_index = 1 if protocol === "udp"
        else
            rules_index = protocol === "tcp" ? 2 : 3
        end

        #check rule, convert IP to number and back to handle weird cases like leading 0s
        if @rules[rules_index][port].nil? || @rules[rules_index][port][number_to_ip(ip_to_number(ip_address))].nil?
            false
        else
            true
        end
    end

    #convert IP string to number to get range for hash
    def ip_to_number(ip_address)
        chunks = ip_address.split('.').map(&:to_i)
        number = (chunks[0] << 24) + (chunks[1] << 16) + (chunks[2] << 8) + chunks[3]
    end

    #convert number to IP string to use as hash key
    def number_to_ip(number)
        chunks = Array.new(4)
        chunks[3] = (255 & number).to_s
        chunks[2] = (((255 << 8) & number) >> 8).to_s
        chunks[1] = (((255 << 16) & number) >> 16).to_s
        chunks[0] = (number >> 24).to_s
        chunks.join(".")
    end

    def get_rules
        @rules
    end
end

#testing
fw = Firewall.new("./fw.csv")
#puts fw.accept_packet("inbound", "udp", 53, "192.168.2.1")
#puts fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11")
#p fw.get_rules[2][10234]

#puts fw.accept_packet("inbound", "tcp", 81, "192.168.1.2")
#puts fw.accept_packet("inbound", "udp", 24, "52.12.48.92")
#puts fw.accept_packet("inbound", "tcp", 22, "192.168.01.1")

#too slow inbound,udp,12-29999,192.168.1.1-192.169.2.1