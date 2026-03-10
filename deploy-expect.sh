#!/usr/bin/expect -f
set timeout 180

spawn ecloud compute app upgrade 0x8eF53C5F2194ec99F20ae20266f34b4f18F6dec5 \
  --image-ref ghcr.io/claw178-design/tee-attestor-real:latest \
  --log-visibility public \
  --environment sepolia \
  --instance-type g1-standard-4t \
  --resource-usage-monitoring enable \
  --private-key 0x038c5033e7a4be6af6ae4a23461f8204478c3a963f677f66b0108e7972193631 \
  --verbose

# Answer "Build from verifiable source?" -> N
expect "verifiable source" { send "N\r" }

# If Dockerfile detected, select "Deploy existing image from registry" -> down arrow + enter
expect {
  "Choose deployment method" { send "\033\[B\r" }
  "Choose an option" { send "\033\[B\r" }
  "env file" { send "\033\[B\r" }
}

# Handle env file prompt if it appears after deployment method
expect {
  "Choose an option" { send "\033\[B\r" }
  "env file" { send "\033\[B\r" }
  "successfully" { puts "\n\nUpgrade succeeded!"; exit 0 }
  "Upgrade" { }
  timeout { puts "\n\nTimeout waiting for deploy"; exit 1 }
  eof { puts "\n\nProcess ended"; exit 0 }
}

# Wait for completion
expect {
  "successfully" { puts "\n\nUpgrade succeeded!" }
  "Upgrade" { puts "\n\nUpgrade in progress..." }
  "error" { puts "\n\nUpgrade error!" }
  timeout { puts "\n\nTimeout!" }
  eof { puts "\n\nProcess ended" }
}

expect eof
