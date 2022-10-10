# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(remove-normal) begin
(remove-normal) create quux.dat
(remove-normal) remove quux.dat
(remove-normal) remove quux.dat again
(remove-normal) end
remove-normal: exit(0)
EOF
pass;
