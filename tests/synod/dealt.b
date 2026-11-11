use("fuuin", %i[combine offer sign])

def main()
  a = threshold_share_import("SHARE_A")
  c = threshold_share_import("SHARE_C")
  oa = offer(a, "fragment root")
  oc = offer(c, "fragment root")
  commitments = [oa.commitment, oc.commitment]
  parts = [
    sign("fragment root", a, {nonces: oa.nonces, commitments:}),
    sign("fragment root", c, {nonces: oc.nonces, commitments:})
  ]
  write_stdout(
    json_stringify(
      {
        key: a.key,
        shares: [threshold_share_export(a), threshold_share_export(c)],
        sig: combine(
          parts,
          {group: "GROUP", data: "fragment root", commitments:}
        )
      }
    )
  )
end
