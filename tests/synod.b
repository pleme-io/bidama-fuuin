@moduledoc """
fuuin's threshold signing, proven end to end: each test writes a program from `tests/synod`, with a fixture project's Bluefile when it needs one, runs it with the blue running these tests, and checks every signature with the host's own Ed25519 verifier.

    allowing(["mpc_threshold"]) #=> ["--allow", "mpc_threshold"]
"""

use("fairu", [:write_tree])
use("retsu", %i[first flat_map is_empty push reject])
use("shisutemu", %i[status_of stderr_of stdout_of])
use("tesuto", [:fresh_dir])

@doc """
fixture: a path under this repository's `tests`, read from GEN_ROOT under the check and from the working directory otherwise.

    ends_with?(fixture("synod/sign.b"), "tests/synod/sign.b") #=> true
"""
def fixture(rel)
  path_join(path_join(getenv("GEN_ROOT", "."), "tests"), rel)
end

@doc """
blue: run the blue running these tests with `args`; the capture.
"""
def blue(args)
  exec_with_env([], self_exe, *args)
end

@doc """
allowing: the `--allow` arguments for each capability named.

    allowing(%w[entropy network]) #=> ["--allow", "entropy", "--allow", "network"]
"""
def allowing(caps)
  flat_map(caps, (c) -> ["--allow", c])
end

@doc """
program: a `tests/synod` program as a [name, text] pair.
"""
def program(name)
  [name, read_file(fixture("synod/#{name}"))]
end

@doc """
placed: a fresh directory holding each [name, text] file.
"""
def placed(label, files)
  dir = fresh_dir("fuuin-synod-#{label}")
  write_tree(dir, files)
  dir
end

@doc """
project: a fresh project holding `bluefile` and each program, locked.
"""
def project(label, bluefile, programs)
  dir = placed(label, push(programs, ["Bluefile", bluefile]))
  cap = blue(["lock", dir])
  if status_of(cap) != 0
    raise(:synod, "blue lock #{label}: #{stderr_of(cap)}")
  end
  dir
end

@doc """
bluefile: the Bluefile of the fixture project `tests/synod/<kind>`.
"""
def bluefile(kind)
  read_file(fixture("synod/#{kind}/Bluefile"))
end

@doc """
run_json: a program run quietly with `allow`; its stdout read as JSON, and a failed run raised with its output.
"""
def run_json(file, allow)
  cap = blue(append(%w[run --quiet], allowing(allow), [file]))
  if status_of(cap) != 0
    raise(:synod, "blue run #{file}: #{stdout_of(cap)}#{stderr_of(cap)}")
  end
  json_read(trim(stdout_of(cap)))
end

@doc """
lock_of: a project's Bluefile.lock, read.
"""
def lock_of(dir)
  json_read(read_file(path_join(dir, "Bluefile.lock")))
end

@doc """
every?: whether `pred` holds for each item of `xs`.

    every?((x) -> x > 0, [1, 2]) #=> true
    every?((x) -> x > 1, [1, 2]) #=> false
"""
def every?(pred, xs)
  is_empty(reject(pred, xs))
end

@doc """
same?: whether every item of `xs` equals the first.

    same?([1, 1]) #=> true
    same?([1, 2]) #=> false
"""
def same?(xs)
  every?((x) -> x == first(xs), xs)
end

test "a threshold word outside a hold without mpc-threshold is a fatal breach no rescue sees"
  dir = placed("breach", [program("breach.b")])
  file = path_join(dir, "breach.b")
  every?(
    fn(allow)
      o = blue(append(%w[run --quiet], allowing(allow), [file]))
      assert status_of(o) == 77
      assert contains?(
        stderr_of(o),
        "`threshold_deal` reaches the host (mpc-threshold)"
      )
      assert not contains?(stdout_of(o), "swallowed")
      assert not contains?(stdout_of(o), "after")
      true
    end,
    [["none"], %w[entropy network]]
  )
  o = blue(["run", "--quiet", "--allow", "mpc_threshold", file])
  assert status_of(o) == 0
  assert ends_with?(stdout_of(o), "after")
  assert contains?(stdout_of(o), "shares:")
  named = placed("named", [program("named.b")])
  o = blue(["run", "--quiet", "--allow", "none", path_join(named, "named.b")])
  assert status_of(o) == 1
  assert contains?(
    stderr_of(o),
    "`threshold_deal` reaches the host (mpc-threshold), which this run does not allow"
  )
  assert stdout_of(o) == ""
  rm_rf(dir)
  rm_rf(named)
end

test "a two of three group signs with any two shares and one share alone cannot"
  dir = placed("signing", [program("signing.b")])
  j = run_json(path_join(dir, "signing.b"), ["mpc_threshold"])
  key = j["key"]
  assert j["verified"] == [true, true, true]
  assert j["other"] == [false, false, false]
  assert j["alone"] == %w[refused refused]
  sigs = j["sigs"]
  assert length(sigs) == 3
  assert every?((s) -> ed25519_verify(key, "release v1", s), sigs)
  assert every?((s) -> not ed25519_verify(key, "release v2", s), sigs)
  assert sigs[0] != sigs[1]
  assert length(j["shares"]) == 3
  rm_rf(dir)
end

test "shares tameshi deals sign in blue under tameshi's group key"
  deal = json_read(read_file(fixture("fixtures/tameshi-deal.json")))
  text = replace(
    replace(
      replace(
        read_file(fixture("synod/dealt.b")),
        "SHARE_A",
        deal["shares"][0]
      ),
      "SHARE_C",
      deal["shares"][2]
    ),
    "GROUP",
    deal["group"]
  )
  dir = placed("tameshi", [["dealt.b", text]])
  j = run_json(path_join(dir, "dealt.b"), ["mpc_threshold"])
  assert j["key"] == deal["key"]
  assert j["shares"] == [deal["shares"][0], deal["shares"][2]]
  assert ed25519_verify(deal["key"], "fragment root", j["sig"])
  rm_rf(dir)
end

test "three participants generate a group by DKG that any two sign for"
  dir = placed("dkg", [program("dkg.b")])
  j = run_json(path_join(dir, "dkg.b"), ["mpc_threshold"])
  keys = j["keys"]
  assert length(keys) == 3
  assert same?(keys)
  assert same?(j["groups"])
  assert j["sends"] == 6
  assert j["again"] == "spent"
  assert ed25519_verify(first(keys), "m", j["sig"])
  rm_rf(dir)
end

test "the seeded provider signs the same signature twice with no host entropy"
  dir = project("seeded", bluefile("seeded"), [program("sign.b")])
  lock = lock_of(dir)
  assert lock["capabilities"]["provided"]["mpc-threshold"] ==
    {"provider" => "seeded", "seed" => "synod"}
  assert lock["capabilities"]["ceiling"] == []
  once = run_json(path_join(dir, "sign.b"), [])
  twice = run_json(path_join(dir, "sign.b"), [])
  assert once == twice
  assert ed25519_verify(once["key"], "m", once["sig"])
  other = project(
    "seeded-other",
    replace(bluefile("seeded"), "seed: \"synod\"", "seed: \"another\""),
    [program("sign.b")]
  )
  third = run_json(path_join(other, "sign.b"), [])
  assert third["key"] != once["key"]
  rm_rf(dir)
  rm_rf(other)
end

test "the lock records the mpc-threshold bundle and refuses it past a ceiling"
  dir = project("held", bluefile("held"), [program("sign.b")])
  caps = lock_of(dir)["capabilities"]
  assert caps["ceiling"] == ["mpc-threshold"]
  assert caps["floor"] == ["mpc-threshold"]
  assert caps["packages"]["fuuin"] == ["mpc-threshold"]
  j = run_json(path_join(dir, "sign.b"), [])
  assert ed25519_verify(j["key"], "m", j["sig"])
  refused = placed(
    "refused",
    [["Bluefile", bluefile("refused")], program("sign.b")]
  )
  o = blue(["lock", refused])
  assert status_of(o) != 0
  assert contains?(
    stderr_of(o),
    "[synod-refused] -> [fuuin::generate: needs 'mpc-threshold'] violates ceiling ["
  )
  rm_rf(dir)
  rm_rf(refused)
end
