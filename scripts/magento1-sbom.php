<?php
declare(strict_types=1);
/**
 * magento1-sbom.php — CycloneDX generator for Magento 1 trees that carry no Composer metadata.
 *
 *   php magento1-sbom.php --dir <path> --name <component-name> [--version <v>] [--vendored <file>]
 *
 * Why this exists: Magento 1 module and shop trees have no composer.json and no composer.lock.
 * syft, trivy and cdxgen all return zero components for them, because their PHP analysers are
 * manifest-driven. The only machine-readable dependency data in such a tree is:
 *
 *   app/etc/modules/<Ns>_<Mod>.xml   -> declared modules + <depends> graph
 *   app/code/*&#47;<Ns>/<Mod>/etc/config.xml -> <modules><Ns_Mod><version>
 *   app/Mage.php                     -> the Magento platform version itself
 *
 * Every emitted PURL carries a version. Dependency-Track matches on the version inside the PURL and
 * never on the CycloneDX `version` field, so a version-less component is counted but never analysed.
 *
 * Honest limitation: first-party Extendware/agency modules have near-zero CVE signal — they are not
 * in any advisory database. The vulnerability value of this document sits almost entirely in the
 * vendored third-party libraries, which cannot be discovered automatically and must be supplied via
 * --vendored (a curated JSON list). Treat the rest as inventory, not as monitoring coverage.
 */

$opts = [];
$argvv = array_slice($argv, 1);
for ($i = 0; $i < count($argvv); $i++) {
    if (str_starts_with($argvv[$i], '--')) {
        $opts[substr($argvv[$i], 2)] = $argvv[$i + 1] ?? '';
        $i++;
    }
}
$dir      = $opts['dir']      ?? '';
$name     = $opts['name']     ?? '';
$version  = $opts['version']  ?? '0.0.0';
$vendored = $opts['vendored'] ?? '';
if ($dir === '' || $name === '') {
    fwrite(STDERR, "usage: magento1-sbom.php --dir <path> --name <name> [--version v] [--vendored f]\n");
    exit(2);
}

/** Recursively find files matching a basename, bounded in depth to keep big docroots cheap. */
function findFiles(string $root, string $needle, int $maxDepth = 8): array {
    $out = [];
    if (!is_dir($root)) return $out;
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );
    $it->setMaxDepth($maxDepth);
    foreach ($it as $f) {
        if ($f->isFile() && $f->getFilename() === $needle) $out[] = $f->getPathname();
    }
    return $out;
}

function loadXml(string $path): ?SimpleXMLElement {
    $prev = libxml_use_internal_errors(true);
    $xml = @simplexml_load_file($path);
    libxml_clear_errors();
    libxml_use_internal_errors($prev);
    return $xml ?: null;
}

$components = [];
$dependencies = [];
$seen = [];

// ---- 1. platform version from app/Mage.php ---------------------------------------------------
$platformVersion = null;
foreach (findFiles($dir, 'Mage.php', 4) as $magePhp) {
    $src = (string)file_get_contents($magePhp);
    if (preg_match_all("/'(major|minor|revision|patch)'\s*=>\s*'?(\d+)'?/", $src, $m, PREG_SET_ORDER)) {
        $parts = [];
        foreach ($m as $hit) $parts[$hit[1]] = $hit[2];
        if (isset($parts['major'])) {
            $platformVersion = implode('.', array_filter([
                $parts['major'] ?? null, $parts['minor'] ?? null,
                $parts['revision'] ?? null, $parts['patch'] ?? null,
            ], static fn($v) => $v !== null && $v !== ''));
        }
    }
    if ($platformVersion !== null) break;
}
if ($platformVersion !== null) {
    $components[] = [
        'type' => 'application', 'name' => 'magento/magento1', 'version' => $platformVersion,
        'purl' => 'pkg:generic/magento/magento1@' . rawurlencode($platformVersion),
        'description' => 'Magento 1 platform (end of life 2020-06-30)',
    ];
    $seen['magento/magento1'] = true;
}

// ---- 2. module versions from etc/config.xml --------------------------------------------------
$moduleVersions = [];
foreach (findFiles($dir, 'config.xml', 10) as $cfg) {
    if (!str_contains(str_replace('\\', '/', $cfg), '/etc/config.xml')) continue;
    $xml = loadXml($cfg);
    if ($xml === null || !isset($xml->modules)) continue;
    foreach ($xml->modules->children() as $modName => $node) {
        $v = isset($node->version) ? trim((string)$node->version) : '';
        if ($v !== '') $moduleVersions[(string)$modName] = $v;
    }
}

// ---- 3. declared modules + dependency graph from app/etc/modules/*.xml ------------------------
$declared = [];
$declDir = rtrim($dir, '/') . '/app/etc/modules';
$declFiles = is_dir($declDir) ? (glob($declDir . '/*.xml') ?: []) : [];
// Some vendor build repos nest the tree under a Magento-variant directory (e.g. "1.4.1/app/...").
if ($declFiles === []) {
    foreach (findFiles($dir, 'modules', 3) as $_) { /* no-op: handled by recursive scan below */ }
    foreach (glob(rtrim($dir, '/') . '/*/app/etc/modules/*.xml') ?: [] as $f) $declFiles[] = $f;
}
foreach ($declFiles as $f) {
    $xml = loadXml($f);
    if ($xml === null || !isset($xml->modules)) continue;
    foreach ($xml->modules->children() as $modName => $node) {
        $mod = (string)$modName;
        $declared[$mod] = true;
        $deps = [];
        if (isset($node->depends)) {
            foreach ($node->depends->children() as $depName => $_ignored) $deps[] = (string)$depName;
        }
        $dependencies[$mod] = $deps;
    }
}

foreach (array_keys($declared) as $mod) {
    if (isset($seen[$mod])) continue;
    // A module with no discoverable version is deliberately pinned to 0.0.0-unknown rather than
    // emitted version-less: a version-less PURL is silently dropped by Dependency-Track, whereas an
    // explicit sentinel is visible and auditable.
    $v = $moduleVersions[$mod] ?? '0.0.0-unknown';
    [$ns, $short] = array_pad(explode('_', $mod, 2), 2, '');
    $components[] = [
        'type' => 'library', 'name' => $mod, 'version' => $v,
        'group' => $ns,
        'purl' => 'pkg:generic/' . rawurlencode($ns) . '/' . rawurlencode($short ?: $mod)
                  . '@' . rawurlencode($v),
        'description' => 'Magento 1 module (first-party or vendor; not present in any advisory DB)',
    ];
    $seen[$mod] = true;
}

// ---- 4. curated vendored third-party libraries ------------------------------------------------
// This is where the actual CVE signal lives. Format: [{"name":"...","version":"...","purl":"..."}]
if ($vendored !== '' && is_file($vendored)) {
    $list = json_decode((string)file_get_contents($vendored), true, 512, JSON_THROW_ON_ERROR);
    foreach ($list as $lib) {
        if (empty($lib['purl']) || !str_contains((string)$lib['purl'], '@')) {
            fwrite(STDERR, "[magento1-sbom] skipping vendored entry without versioned purl: "
                         . ($lib['name'] ?? '?') . "\n");
            continue;
        }
        $components[] = [
            'type' => 'library',
            'name' => $lib['name'] ?? $lib['purl'],
            'version' => $lib['version'] ?? '',
            'purl' => $lib['purl'],
            'description' => $lib['description'] ?? 'vendored third-party library (curated)',
        ] + (isset($lib['modified']) ? ['modified' => (bool)$lib['modified']] : []);
    }
}

// ---- 5. emit ----------------------------------------------------------------------------------
$rootRef = 'root-' . $name;
$deps = [['ref' => $rootRef, 'dependsOn' => array_map(
    static fn(array $c) => $c['purl'], $components)]];
foreach ($dependencies as $mod => $on) {
    if (!isset($seen[$mod])) continue;
    $refs = [];
    foreach ($on as $d) {
        foreach ($components as $c) if ($c['name'] === $d) { $refs[] = $c['purl']; break; }
    }
    if ($refs !== []) {
        foreach ($components as $c) {
            if ($c['name'] === $mod) { $deps[] = ['ref' => $c['purl'], 'dependsOn' => $refs]; break; }
        }
    }
}
foreach ($components as &$c) { $c['bom-ref'] = $c['purl']; } unset($c);

$bom = [
    'bomFormat'   => 'CycloneDX',
    'specVersion' => '1.6',
    'version'     => 1,
    'metadata'    => [
        'tools' => ['components' => [[
            'type' => 'application', 'name' => 'magento1-sbom.php', 'version' => '1.0.0',
        ]]],
        'component' => [
            'type' => 'application', 'name' => $name, 'version' => $version,
            'bom-ref' => $rootRef,
            'purl' => 'pkg:generic/' . str_replace('/', '%2F', $name) . '@' . rawurlencode($version),
        ],
    ],
    'components'   => array_values($components),
    'dependencies' => $deps,
];
echo json_encode($bom, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
