-- Offline tests: capture packet dissections instead of sending packets.
-- Run after the three --lua-init files, with --intercept=0.
-- Does not install netfilter rules or send any network packets.
local captured = {}
local original_sender = rawsend_dissect
rawsend_dissect = function(dis, opts, reconstruct)
    captured[#captured+1] = {dis=deepcopy(dis), opts=deepcopy(opts or {})}
    return true
end

local function check(value, message)
    if not value then error('ALT11 TEST FAIL: ' .. message) end
end

local function overlap_pattern(blob, length)
    return string.sub(string.rep(blob, math.ceil(length / #blob)), 1, length)
end

-- Markers are offsets; the C API returns 1-based indices to Lua by default.
check(resolve_multi_pos('abcd', 'unknown', '1')[1]==2, 'marker 1 must resolve to Lua index 2')
check(resolve_multi_pos('abcd', 'unknown', '1', true)[1]==1, 'zero-based resolver must return offset 1')
print('ALT11 marker check: pos=1 -> Lua index 2 (split after one byte)')

local function tcp_fixture(payload, ptype, args)
    return {
        outgoing=true, l7payload=ptype, arg=args, tcp_mss=1460,
        func_instance='alt11_tcp_test', track={lua_state={}},
        dis={
            ip={ip_id=900, ip_ttl=64, ip_p=IPPROTO_TCP, options=''},
            tcp={th_seq=100000, th_ack=12345, th_flags=TH_ACK+TH_PUSH,
                 options={{kind=TCP_KIND_NOOP}, {kind=TCP_KIND_TS, data=bu32(900000)..bu32(777)}}},
            payload=payload
        }
    }
end

local google = {tls='alt11_tls_google', http='alt11_http_default',
                pattern='alt11_tls_google', seqovl='681', repeats='8', ip_id='zero'}
captured={}
local d=tcp_fixture(alt11_tls_google, 'tls_client_hello', google)
local timestamp=d.dis.tcp.options[2].data
check(alt11_tcp(nil,d)==VERDICT_DROP, 'Google TLS must replace original packet')
check(#captured==3, 'Google: one fake + two real segments')
check(captured[1].dis.payload==alt11_tls_google, 'Google fake bytes')
check(tonumber(captured[1].opts.repeats)==8, 'Google fake repeats=8')
check(u32(captured[1].dis.tcp.options[1].data)==300000, 'fake timestamp is shifted by -600000')
check(captured[2].dis.payload==overlap_pattern(alt11_tls_google,681)..string.sub(alt11_tls_google,1,1), '681-byte seqovl + one real byte')
check(captured[2].dis.tcp.th_seq==100000-681, 'overlap sequence')
check(captured[3].dis.payload==string.sub(alt11_tls_google,2), 'second part begins after first byte')
check(captured[3].dis.tcp.th_seq==100001, 'second part sequence')
for i=2,3 do
    check(tonumber(captured[i].opts.repeats)==1, 'originals are sent once')
    check(captured[i].dis.tcp.options[1].data==timestamp, 'real timestamp is not shifted')
end
for i=1,3 do check(captured[i].dis.ip.ip_id==0, 'Google ip-id zero') end
check(d.dis.tcp.options[2].data==timestamp and d.arg==google, 'input packet and args remain intact')

local general={tls='alt11_stun2,alt11_tls_max', http='alt11_tls_max',
               pattern='alt11_tls_max',seqovl='664',repeats='8'}
captured={}
d=tcp_fixture(alt11_tls_google,'tls_client_hello',general)
alt11_tcp(nil,d)
check(#captured==4, 'general TLS: two different fakes + two real segments')
check(captured[1].dis.payload==alt11_stun2 and captured[2].dis.payload==alt11_tls_max, 'TLS fake order: stun2, max.ru')
check(tonumber(captured[1].opts.repeats)==8 and tonumber(captured[2].opts.repeats)==8, 'both TLS fakes repeat 8 times')
check(captured[3].dis.payload==overlap_pattern(alt11_tls_max,664)..string.sub(alt11_tls_google,1,1), '664-byte overlap pattern')

captured={}
local google_http='GET / HTTP/1.1\r\nHost: example.org\r\n\r\n'
d=tcp_fixture(google_http,'http_req',google)
alt11_tcp(nil,d)
check(#captured==3 and captured[1].dis.payload==alt11_http_default, 'Google HTTP uses the standard HTTP fake')
check(#alt11_http_default==263, 'standard HTTP fake is complete, including all headers')
check(captured[3].dis.payload==string.sub(google_http,2), 'Google HTTP split after byte one')

captured={}
local http='GET / HTTP/1.1\r\nHost: example.org\r\n\r\n'
d=tcp_fixture(http,'http_req',general)
alt11_tcp(nil,d)
check(#captured==3 and captured[1].dis.payload==alt11_tls_max, 'HTTP uses MAX TLS bytes as in the BAT')
check(captured[3].dis.payload==string.sub(http,2), 'HTTP split after byte one')

captured={}
d=tcp_fixture('opaque game request','unknown',general)
alt11_tcp(nil,d)
check(#captured==0, 'ordinary TCP profile leaves unknown payload alone')
local game=deepcopy(general)
game.any='1'; game.unknown='alt11_stun2,alt11_tls_max'
d=tcp_fixture('opaque game request','unknown',game)
alt11_tcp(nil,d)
check(#captured==4 and captured[1].dis.payload==alt11_stun2 and captured[2].dis.payload==alt11_tls_max, 'Game Filter unknown TCP fakes')

captured={}
d=tcp_fixture(alt11_tls_google,'tls_client_hello',google)
d.outgoing=false
alt11_tcp(nil,d)
check(#captured==0,'incoming TCP is not altered')

captured={}
d=tcp_fixture(alt11_tls_google,'tls_client_hello',google)
d.replay=true; d.replay_piece=1; d.replay_piece_last=false; d.reasm_data=alt11_tls_google
alt11_tcp(nil,d)
check(#captured==3,'first replay piece is sent once')
d.replay_piece=2; d.replay_piece_last=true
check(alt11_tcp(nil,d)==VERDICT_DROP and #captured==3,'remaining replay piece is dropped without resending')

local function udp_fixture(ptype,args)
    return {outgoing=true,l7payload=ptype,arg=args,func_instance='alt11_udp_test',
        dis={ip={ip_id=901,ip_ttl=64,ip_p=IPPROTO_UDP,options=''},udp={},payload='original UDP payload'}}
end
captured={}
d=udp_fixture('quic_initial',{mode='quic',quic='alt11_quic_google',repeats='11'})
check(alt11_udp(nil,d)==nil,'UDP original remains in the normal packet path')
check(#captured==1 and captured[1].dis.payload==alt11_quic_google and tonumber(captured[1].opts.repeats)==11,'QUIC fake repeats=11')
captured={}
d=udp_fixture('stun',{mode='discord',active='alt11_discord_active',repeats='6'})
alt11_udp(nil,d)
check(#captured==1 and captured[1].dis.payload==alt11_discord_active and tonumber(captured[1].opts.repeats)==6,'Discord/STUN active fake')
captured={}
d=udp_fixture('unknown',{mode='game',active='alt11_game_active',repeats='10'})
alt11_udp(nil,d)
check(#captured==1 and captured[1].dis.payload==alt11_game_active and tonumber(captured[1].opts.repeats)==10,'unknown game UDP fake')
captured={}
d=udp_fixture('quic_initial',{mode='game',active='alt11_game_active',repeats='10'})
alt11_udp(nil,d)
check(#captured==1 and captured[1].dis.payload==string.rep('\0',620),'known QUIC in Game Filter keeps nfqws1 default')
captured={}
d=udp_fixture('wireguard_initiation',{mode='quic',quic='alt11_quic_google',repeats='11'})
alt11_udp(nil,d)
check(#captured==1 and captured[1].dis.payload==string.rep('\0',64),'known UDP default uses 64 zeros')

rawsend_dissect=original_sender
print('ALT11 offline packet tests: PASS (TCP, HTTP, QUIC, Discord, Game Filter, replay)')
