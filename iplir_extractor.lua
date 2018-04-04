--[[
 * 
 * Inspired by https://github.com/volvet/h264extractor
 *
 *]]

do
    local cap_time              = Field.new("frame.time_epoch")
    local cap_len               = Field.new("frame.cap_len")

    local eth_data              = Field.new("eth")
    local ip_data               = Field.new("ip")
    local iplir_data            = Field.new("iplir")
    local iplir_encap_data      = Field.new("iplir.encap_data")
    -- local iplir_decrypt_err     = Field.new("iplir.decrypt_err")
    local iplir_encap_tm        = Field.new("iplir.enc_info.timestamp")
    local iplir_encap_proto     = Field.new("iplir.enc_info.orig_proto")
    local iplir_dec_src_ip      = Field.new("iplir.enc_info.source_ip")
    local iplir_dec_dst_ip      = Field.new("iplir.enc_info.dest_ip")


    local output_filename = "extracted.pcap"

    local function remove_iplir_header()
        local iplir_tap = Listener.new("ip", "iplir")
        local text_window = TextWindow.new("IPLIR extractor")
        local fp = io.open(output_filename, "wb")

        ----
        -- write pcap header
        ----
        fp:write(string.char(0xD4, 0xC3, 0xB2, 0xA1))

        fp:write(string.char(0x02, 0x00, 0x04, 0x00))
        fp:write(string.char(0x00, 0x00, 0x00, 0x00))
        fp:write(string.char(0x00, 0x00, 0x00, 0x00))
        fp:write(string.char(0xFF, 0xFF, 0x00, 0x00))
        fp:write(string.char(0x01, 0x00, 0x00, 0x00))
        fp:flush()

        local packet_tot_count = 0
        local packet_skip_count = 0
        local packet_err_count = 0

        local function log(info)
            text_window:append(info)
            text_window:append("\n")
        end

        local function int2bytes(value)

            return string.char(
                bit.band(value, 0xff),
                bit.arshift( bit.band(value, 0xff00), 8 ),
                bit.arshift( bit.band(value, 0xff0000), 16 ),
                bit.arshift( bit.band(value, 0xff000000), 24 )
            )
        end

        local function int2bytearray(value)
            -- log("[int2bytearray] value = "..tostring(value))
            
            return
                ByteArray.new( tostring( bit.band(value, 0xff) ) )..
                ByteArray.new( tostring( bit.arshift( bit.band(value, 0xff00), 8 ) ) )..
                ByteArray.new( tostring( bit.arshift( bit.band(value, 0xff0000), 16 ) ) )..
                ByteArray.new( tostring( bit.arshift( bit.band(value, 0xff000000), 24 ) ) )
        end

        local function ip4str2bytearray(ip_str)
            local b1, b2, b3, b4 = string.match( ip_str, "(%d+).(%d+).(%d+).(%d+)" )
            -- log("[ip4str2bytearray] b1: "..b1..", b2: "..b2..", b3:"..b3..", b4:"..b4)

            local bytes = ByteArray.new("00 00 00 00")

            bytes:set_index(0, tonumber(b1))
            bytes:set_index(1, tonumber(b2))
            bytes:set_index(2, tonumber(b3))
            bytes:set_index(3, tonumber(b4))

            return bytes
        end

        if fp == nil then 
            log("open dump file fail")
        end
        
        
        -- me: this seems to be called for final packets after IP defrag, and never for frames with IP frags
        function iplir_tap.packet(pinfo, tvb)
            packet_tot_count = packet_tot_count + 1

            -- log("packet num = "..tostring(packet_tot_count))

            -- check if this is IPLIR packet
            if iplir_encap_data() == nil then
                packet_skip_count = packet_skip_count + 1

                -- log("** non IPLIR of failed to decrypt, pkt#"..tostring(packet_tot_count))
            else
                -- synonym for 'iplir.decrypt_err'
                local err = iplir_encap_tm()
                if err == nil then                    
                    packet_err_count = packet_err_count + 1

                    log("*** Error-ed IPLIR pkt#"..tostring(packet_tot_count))
                    return
                end

                if #iplir_encap_data() > 0 then
                    local sec, usec = string.match( tostring(cap_time().value), "(%d+).(%d+)" )

                    ----    
                    -- write packet header
                    ----
                    fp:write(int2bytes(tonumber(sec)))
                    fp:write(int2bytes(tonumber(usec / 1000)))

                    -- local cap_len = tonumber(cap_len().value)
                    local cap_len = tonumber(eth_data().value:tvb():len() + ip_data().value:tvb():len() + iplir_encap_data().value:tvb():len())
                    fp:write(int2bytes(cap_len))
                    fp:write(int2bytes(cap_len))


                    local ind


                    ----
                    -- write ETH hdr
                    ----
                    ethh_tvb = eth_data().value:tvb()

                    ind = 0
                    while ind < ethh_tvb:len() do
                        fp:write( string.char(ethh_tvb(ind, 1):uint()) )
                        ind = ind + 1
                    end


                    local encap_tvb = iplir_encap_data().value:tvb()


                    ----
                    -- write IP hdr
                    ----
                    local iph_tvb = ip_data().value:tvb()
                    local iph_bytes = iph_tvb:range(0, iph_tvb:len()):bytes()

                    -- protocol
                    local protocol = tonumber(iplir_encap_proto().value)

                    iph_bytes:set_index( 9, protocol )
                    
                    -- cksum
                    -- TODO: recalc
                    iph_bytes:set_index( 10, 0 )
                    iph_bytes:set_index( 11, 0 )
                    
                    -- flags & frag_offset
                    iph_bytes:set_index( 6, 0 )
                    iph_bytes:set_index( 7, 0 )
                    
                    -- total length
                    local tot_len = iph_tvb:len() + encap_tvb:len()
                    iph_bytes:set_index( 2, bit.arshift( bit.band(tot_len, 0xff00), 8 ) )
                    iph_bytes:set_index( 3, bit.band(tot_len, 0xff) )

                    -- src.ip & dst.ip
                    local iph_ext_size = 0
                    if iph_bytes:len() > 20 then
                        iph_ext_size = iph_bytes:len() - 20
                    end

                    src_ip_bytes = ip4str2bytearray( tostring(iplir_dec_src_ip().value) )
                    dst_ip_bytes = ip4str2bytearray( tostring(iplir_dec_dst_ip().value) )

                    iph_bytes = iph_bytes:subset(0, 12)..src_ip_bytes..dst_ip_bytes
                    if iph_ext_size > 0 then
                        iph_bytes = iph_bytes + iph_bytes:subset(20, iph_ext_size)
                    end

                    iph_tvb = ByteArray.tvb(iph_bytes)
                    
                    ind = 0
                    while ind < iph_tvb:len() do
                        fp:write( string.char(iph_tvb(ind, 1):uint()) )
                        ind = ind + 1
                    end


                    ----
                    -- write encapsulated payload (transport header with payload)
                    ----
                    if protocol == 17 or protocol == 6 then                    
                        local encap_bytes = encap_tvb:range(0, encap_tvb:len()):bytes()

                        -- TODO: recalc
                        if protocol == 17 then
                            encap_bytes:set_index(6, 0)
                            encap_bytes:set_index(7, 0)
                        elseif protocol == 6 then
                            encap_bytes:set_index(16, 0)
                            encap_bytes:set_index(17, 0)
                        end

                        encap_tvb = ByteArray.tvb(encap_bytes)
                    end

                    ind = 0
                    while ind < encap_tvb:len() do
                        fp:write( string.char(encap_tvb(ind, 1):uint()) )
                        ind = ind + 1
                    end

                    fp:flush()
                end
            end -- if #iplir_encap_data() > 0 then
        end -- if iplir_encap_data() == nil then
        
        function iplir_tap.reset()
        end
        
        function iplir_tap.draw() 
        end
        
        local function remove() 
            if fp then 
                fp:close()
                fp = nil
            end
            iplir_tap:remove()
        end 
        
        text_window:set_atclose(remove)
        
        retap_packets()
        
        local decrypted_pkt_count = packet_tot_count - packet_err_count - packet_skip_count

        log("")
        log("Total processed: "..tostring(packet_tot_count))
        log("Decrypted: "..tostring(decrypted_pkt_count))
        log("IPLIR decrypt error (wrong MAC, etc.): "..tostring(packet_err_count))
        log("Skipped or decryption failed: "..tostring(packet_skip_count))
    end


    register_menu("Remove IPLIR headers from this capture (will be saved to '"..output_filename.."')", remove_iplir_header, MENU_TOOLS_UNSORTED)
end
