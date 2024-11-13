rule ngrok_binaries {
  meta:
    author      = "@leitosama"
    date        = "2024/Nov/13"
    description = "Find NGROK agent binaries"
    filetype    = "exe"
  strings:
    $s1 = "ngrok" fullword
    $s2 = "go.ngrok.com"
    $s3 = "https://s3.amazonaws.com/dns.ngrok.com/tunnel.json"
    $s4 = "ngrokService"
    $s5 = "HTTPRoundTrip_KeyVal"
  condition:
   (3 of ($s*))
}
