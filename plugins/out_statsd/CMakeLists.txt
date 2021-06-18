set(src
  statsd.c
  statsd_conf.c
  )

FLB_PLUGIN(out_statsd "${src}" "mk_core")
