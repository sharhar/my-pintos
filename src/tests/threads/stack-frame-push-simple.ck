# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(stack-frame-push-simple) begin
(stack-frame-push-simple) Created thread
(stack-frame-push-simple) Helper thread start
(stack-frame-push-simple) Your stack has been hacked!
(stack-frame-push-simple) Helper thread end
(stack-frame-push-simple) Joined thread
(stack-frame-push-simple) PASS
(stack-frame-push-simple) end
EOF
pass;
