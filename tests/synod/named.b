def main()
  g = threshold_deal(2, 3) rescue "swallowed"
  write_stdout(to_s(g))
end
