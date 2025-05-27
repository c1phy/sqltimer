class Sqltimer < Formula
  desc "Time-based SQL Injection Detection Tool"
  homepage "https://github.com/c1phy/sqltimer"
  url "https://github.com/c1phy/sqltimer/archive/refs/tags/v0.4.4.tar.gz"
  sha256 "7e7f782c9b147ac2b943de208ba048d926da352f5fbf7b8c6efe33a64c77c674"
  license "MIT"
  head "https://github.com/c1phy/sqltimer.git", branch: "main"

  depends_on "go" => :build

  def install
    system "go", "build", *std_go_args(ldflags: "-s -w")
  end

  test do
    assert_match "sqltimer", shell_output("#{bin}/sqltimer --help")
  end
end
