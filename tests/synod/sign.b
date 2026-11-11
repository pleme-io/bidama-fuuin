use("fuuin", %i[combine generate offer sign])

def main()
  g = generate(:threshold, {min: 2, max: 3})
  a = g.shares[0]
  b = g.shares[1]
  oa = offer(a, "m")
  ob = offer(b, "m")
  commitments = [oa.commitment, ob.commitment]
  parts = [
    sign("m", a, {nonces: oa.nonces, commitments:}),
    sign("m", b, {nonces: ob.nonces, commitments:})
  ]
  write_stdout(
    json_stringify(
      {
        key: g.key,
        sig: combine(parts, {group: g.group, data: "m", commitments:})
      }
    )
  )
end
