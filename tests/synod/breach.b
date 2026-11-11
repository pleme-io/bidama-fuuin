use("fuuin", [:generate])

def main()
  g = generate(:threshold, {min: 2, max: 3}) rescue "swallowed"
  write_stdout(to_s(g))
  write_stdout("after")
end
