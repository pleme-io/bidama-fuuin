use("fuuin", %i[combine generate offer sign])
use("kyohi", [:raised])
use("retsu", %i[first last])
use("shomei", [:verify?])

def signed(g, picks, data)
  offers = map((p) -> offer(g.shares[p - 1], data), picks)
  commitments = map((o) -> o.commitment, offers)
  parts = map(
    fn(i)
      sign(
        data,
        g.shares[picks[i] - 1],
        {nonces: offers[i].nonces, commitments:}
      )
    end,
    range(length(picks))
  )
  combine(parts, {group: g.group, data:, commitments:})
end

def alone(g, data)
  s = first(g.shares)
  o = offer(s, data)
  t = offer(last(g.shares), data)
  both = [o.commitment, t.commitment]
  part = sign(data, s, {nonces: o.nonces, commitments: both})
  [
    raised(
      fn()
        sign(
          data,
          s,
          {nonces: offer(s, data).nonces, commitments: [o.commitment]}
        )
      end
    ),
    raised(() -> combine([part], {group: g.group, data:, commitments: both}))
  ]
end

def main()
  g = generate(:threshold, {min: 2, max: 3})
  sigs = map(
    (picks) -> signed(g, picks, "release v1"),
    [[1, 2], [1, 3], [2, 3]]
  )
  write_stdout(
    json_stringify(
      {
        key: g.key,
        group: g.group,
        sigs:,
        verified: map((s) -> verify?("release v1", s, g.key), sigs),
        other: map((s) -> verify?("release v2", s, g.key), sigs),
        alone: alone(g, "release v1"),
        shares: map((s) -> threshold_share_export(s), g.shares)
      }
    )
  )
end
