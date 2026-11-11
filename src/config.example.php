<?php
/**
 * Seal ID configuration.
 * Copy this file to config.php and change setup_code before opening setup.php.
 * config.php is never published (git-ignored, blocked by .htaccess).
 */
return [
    // Needed once, to run setup.php. Use something long and random.
    'setup_code' => 'change-me-to-something-secret',

    // Where Seal ID keeps its data. Default: a ".sealid-data" folder NEXT TO
    // the install folder (outside the web root). Use an absolute path to change it.
    'data_dir' => null,

    // Who tests "can other Seal IDs reach you?" from the outside.
    'reach_helper' => 'https://id.bristow.ch',

    // How often (hours) verified proofs are re-checked when the profile is viewed.
    'recheck_hours' => 6,

    // Set to true ONLY if you lost your key and need to start a new identity
    // chain at the same address (setup.php then works again). Set it back afterwards.
    'allow_reset' => false,
];
