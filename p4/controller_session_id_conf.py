OBF_TRAFFIC_PORT = 40

# After entering bfrt:
# maxlen is counted from the preamble and start-of-frame delimiter before the MAC frame.

bfrt.mirror.cfg.clear()

# IP payload x + IP header 20 + MAC header 14 = x + 34 + extra bytes (10B?),
# which tends to vary.

bfrt.mirror.cfg.add_with_normal(sid=1, session_enable=True, direction="INGRESS", \
ucast_egress_port=OBF_TRAFFIC_PORT, egress_port_queue=1, \
ucast_egress_port_valid=True, max_pkt_len=8+34+10)

bfrt.mirror.cfg.add_with_normal(sid=2, session_enable=True, direction="INGRESS", \
ucast_egress_port=OBF_TRAFFIC_PORT, egress_port_queue=1, \
ucast_egress_port_valid=True, max_pkt_len=16+34+10)

bfrt.mirror.cfg.add_with_normal(sid=3, session_enable=True, direction="INGRESS", \
ucast_egress_port=OBF_TRAFFIC_PORT, egress_port_queue=1, \
ucast_egress_port_valid=True, max_pkt_len=24+34+10)

bfrt.mirror.cfg.add_with_normal(sid=4, session_enable=True, direction="INGRESS", \
ucast_egress_port=OBF_TRAFFIC_PORT, egress_port_queue=1, \
ucast_egress_port_valid=True, max_pkt_len=32+34+10)

bfrt.mirror.cfg.add_with_normal(sid=5, session_enable=True, direction="INGRESS", \
ucast_egress_port=OBF_TRAFFIC_PORT, egress_port_queue=1, \
ucast_egress_port_valid=True, max_pkt_len=40+34+10)

bfrt.mirror.cfg.add_with_normal(sid=6, session_enable=True, direction="INGRESS", \
ucast_egress_port=OBF_TRAFFIC_PORT, egress_port_queue=1, \
ucast_egress_port_valid=True, max_pkt_len=48+34+10)

bfrt.mirror.cfg.add_with_normal(sid=7, session_enable=True, direction="INGRESS", \
ucast_egress_port=OBF_TRAFFIC_PORT, egress_port_queue=1, \
ucast_egress_port_valid=True, max_pkt_len=56+34+10)

bfrt.mirror.cfg.add_with_normal(sid=8, session_enable=True, direction="INGRESS", \
ucast_egress_port=OBF_TRAFFIC_PORT, egress_port_queue=1, \
ucast_egress_port_valid=True, max_pkt_len=64+34+10)

bfrt.mirror.cfg.add_with_normal(sid=9, session_enable=True, direction="INGRESS", \
ucast_egress_port=OBF_TRAFFIC_PORT, egress_port_queue=1, \
ucast_egress_port_valid=True, max_pkt_len=72+34+10)

bfrt.mirror.cfg.add_with_normal(sid=10, session_enable=True, direction="INGRESS", \
ucast_egress_port=OBF_TRAFFIC_PORT, egress_port_queue=1, \
ucast_egress_port_valid=True, max_pkt_len=80+34+10)

bfrt.mirror.cfg.add_with_normal(sid=11, session_enable=True, direction="INGRESS", \
ucast_egress_port=OBF_TRAFFIC_PORT, egress_port_queue=1, \
ucast_egress_port_valid=True, max_pkt_len=88+34+10)


# Clear registers.
bfrt.Sec.pipe.Ingress.flow_cnting.clear()
