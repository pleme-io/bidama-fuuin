use("fuuin", %i[combine offer sign])
use("retsu", [:flat_map])

def main()
  starts = map((p) -> threshold_dkg_start(p, 2, 3), [1, 2, 3])
  broadcasts = map((s) -> s.broadcast, starts)
  exchanged = map((s) -> threshold_dkg_exchange(s.secret, broadcasts), starts)
  sends = flat_map(exchanged, (e) -> e.sends)
  done = map(
    (e) -> threshold_dkg_finish(e.secret, broadcasts, sends),
    exchanged
  )
  a = done[0].share
  c = done[2].share
  oa = offer(a, "m")
  oc = offer(c, "m")
  commitments = [oa.commitment, oc.commitment]
  parts = [
    sign("m", a, {nonces: oa.nonces, commitments:}),
    sign("m", c, {nonces: oc.nonces, commitments:})
  ]
  sig = combine(parts, {group: done[1].group, data: "m", commitments:})
  write_stdout(
    json_stringify(
      {
        keys: map((d) -> d.key, done),
        groups: map((d) -> d.group, done),
        sends: length(sends),
        sig:,
        again: threshold_dkg_exchange(starts[0].secret, broadcasts) rescue
          "spent"
      }
    )
  )
end
