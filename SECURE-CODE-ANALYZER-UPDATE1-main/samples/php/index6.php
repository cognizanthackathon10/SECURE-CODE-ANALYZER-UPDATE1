<?php
/**
 * Simple PHP Taint Analysis
 * Detects if user input ($_GET, $_POST, $_REQUEST) flows into dangerous sinks
 */

$code = file_get_contents($argv[1] ?? "test.php");
$lines = explode("\n", $code);

$sources = ["\$_GET", "\$_POST", "\$_REQUEST"];
$sinks   = ["eval", "system", "exec", "shell_exec", "passthru", "popen"];

$taintedVars = [];
$findings = [];

foreach ($lines as $lineNo => $line) {
    $lineNum = $lineNo + 1;

    // Detect taint sources
    foreach ($sources as $src) {
        if (preg_match('/(\$[a-zA-Z_]\w*)\s*=\s*' . preg_quote($src, '/') . '/', $line, $m)) {
            $taintedVars[] = $m[1];
        }
    }

    // Detect sink usage
    foreach ($sinks as $sink) {
        if (preg_match('/\b' . $sink . '\s*\((.*?)\)/', $line, $m)) {
            $arg = $m[1];

            // Direct source in sink
            foreach ($sources as $src) {
                if (strpos($arg, $src) !== false) {
                    $findings[] = "[HIGH] Line $lineNum: Direct user input ($src) passed to $sink()";
                }
            }

            // Tainted variable in sink
            foreach ($taintedVars as $var) {
                if (strpos($arg, $var) !== false) {
                    $findings[] = "[HIGH] Line $lineNum: Tainted variable ($var) passed to $sink()";
                }
            }
        }
    }
}

// Print findings
echo $findings ? implode("\n", $findings) : "No taint vulnerabilities found.\n";
