<?php

// The authentication sources SimpleSAMLphp 2.5.3.1 distributes, and the one the identity provider of the judge signs
// its people in with (issue #788): a username and a password, the people and their attributes being users.php.
require '/var/simplesamlphp/config-dist/authsources.php.dist';

$config['lab-people'] = [
    'exampleauth:UserPass',
    'users' => require __DIR__ . '/users.php',
];
