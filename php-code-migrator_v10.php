<?php

require 'vendor/autoload.php';

use PhpParser\Error;
use PhpParser\Node;
use PhpParser\Node\Arg;
use PhpParser\Node\Stmt\Function_;
use PhpParser\Node\Stmt\ClassMethod;
use PhpParser\Node\Scalar\String_;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\PropertyFetch;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitorAbstract;
use PhpParser\ParserFactory;
use PhpParser\PrettyPrinter\Standard;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Symfony\Component\Process\Process;

/**
 * Replacement for parse_str to avoid overwriting global variables.
 */
function parse_str_with_array(string $string, array &$output = []): void
{
    parse_str($string, $parsed);
    $output = $parsed;
}

/**
 * Provides a full list of deprecated functions or extensions,
 * their replacements, and optional rewrite logic for special cases.
 */
function getDeprecatedRules(): array
{
    return [
        // EREG-based
        'ereg' => [
            'replacement' => 'preg_match',
            'rewriteArgs' => function (Node\Expr\FuncCall $node, Logger $logger, array $analysis) {
                if (!empty($node->args)) {
                    $patternArg = $node->args[0];
                    if ($patternArg->value instanceof String_) {
                        $oldVal = $patternArg->value->value;
                        if (!preg_match('#^/.+/[a-zA-Z]*$#', $oldVal)) {
                            $patternArg->value->value = '/' . $oldVal . '/';
                            $logger->info("Wrapped pattern with slashes for preg_match: '/{$oldVal}/'");
                        }
                    }
                }
            }
        ],
        'ereg_replace' => ['replacement' => 'preg_replace'],
        'eregi'        => ['replacement' => 'preg_match'],
        'eregi_replace'=> ['replacement' => 'preg_replace'],
        'ereg extension' => ['replacement' => 'preg_replace'], // for references to the old "ereg" extension

        // MySQL-based
        'mysql_db_query'       => ['replacement' => 'mysqli_select_db'],
        'mysql_escape_string'  => ['replacement' => 'mysqli_real_escape_string'],
        'mysql_query' => [
            'replacement' => 'mysqli_query',
            'rewriteArgs' => function (Node\Expr\FuncCall $node, Logger $logger, array $analysis) {
                $argCount = count($node->args);
                if ($argCount === 1) {
                    // mysql_query($sql) => mysqli_query($conn, $sql)
                    $connVar = pickConnectionVar($analysis['connections'], $logger);
                    $queryArg = $node->args[0];
                    $connArg  = new Arg(new Variable($connVar));
                    $node->args = [$connArg, $queryArg];
                } elseif ($argCount === 2) {
                    // mysql_query($sql, $conn) => mysqli_query($conn, $sql)
                    $queryArg = $node->args[0];
                    $linkArg  = $node->args[1];
                    $node->args = [$linkArg, $queryArg];
                    $logger->info("Swapped args for mysqli_query(\$link, \$query).");
                }
            }
        ],
        'mysql_connect'        => ['replacement' => 'mysqli_connect'],
        'mysql_fetch_array'    => ['replacement' => 'mysqli_fetch_array'],
        'mysql extension'      => ['replacement' => 'mysqli'],

        // Additional MySQL or DB functions
        'each'                 => ['replacement' => 'foreach'],
        'is_real'              => ['replacement' => 'is_float'],

        // Magic Quotes / Removed in 5.4-5.6 era
        'set_magic_quotes_runtime' => ['replacement' => null],
        'magic_quotes_runtime'     => ['replacement' => null],
        'get_magic_quotes_gpc'     => ['replacement' => null],
        'get_magic_quotes_runtime' => ['replacement' => null],
        'session_register'         => ['replacement' => '$_SESSION'],
        'session_unregister'       => ['replacement' => '$_SESSION'],
        'session_is_registered'    => ['replacement' => '$_SESSION'],

        // Others
        'set_socket_blocking' => ['replacement' => 'stream_set_blocking'],
        'split'               => ['replacement' => 'preg_split'],
        'spliti'              => ['replacement' => 'preg_split'],
        'sql_regcase'         => ['replacement' => null],
        'gmp_random'          => ['replacement' => 'gmp_random_range'],
        'iconv_set_encoding'  => ['replacement' => 'ini_set'],
        'iconv_get_encoding'  => ['replacement' => 'ini_get'],
        'utf8_encode'         => ['replacement' => 'mb_convert_encoding'],
        'utf8_decode'         => ['replacement' => 'mb_convert_encoding'],
        'fgetss'              => ['replacement' => 'fgets'],
        'ldap_sort'           => ['replacement' => null],
        'assert' => [
            // This is set to null, but we handle rewriting it if --rewrite-assert is used
            'replacement' => null,
        ],
        'parse_str'           => ['replacement' => 'parse_str_with_array'],
        'mb_ereg'             => ['replacement' => 'preg_match'],
        'mb_ereg_replace'     => ['replacement' => 'preg_replace'],
        'mb_split'            => ['replacement' => 'preg_split'],
        'mb_strcut'           => ['replacement' => 'mb_substr'],
        'mb_strimwidth'       => ['replacement' => 'mb_strimwidth (revised)'],
        'mb_strwidth'         => ['replacement' => 'mb_strlen'],

        // Mysqli function renames
        'mysqli_bind_param'   => ['replacement' => 'mysqli_stmt_bind_param'],
        'mysqli_bind_result'  => ['replacement' => 'mysqli_stmt_bind_result'],
        'mysqli_get_metadata' => ['replacement' => 'mysqli_stmt_result_metadata'],
        'mysqli_fetch'        => ['replacement' => 'mysqli_stmt_fetch'],
        'mysqli_send_long_data' => ['replacement' => 'mysqli_stmt_send_long_data'],
        'mysqli_param_count'  => ['replacement' => 'mysqli_stmt_param_count'],
        'mysqli_stmt_reset'   => ['replacement' => 'mysqli_stmt_reset'],
        'mysqli_stmt_get_result' => ['replacement' => 'mysqli_stmt_get_result'],

        // Others
        'hebrevc' => ['replacement' => 'nl2br(hebrev($str))'],
        'convert_cyr_string' => ['replacement' => 'mb_convert_encoding'],
        'money_format'       => ['replacement' => 'NumberFormatter'],
        'ezmlm_hash'         => ['replacement' => null],
        'restore_include_path' => ['replacement' => "ini_restore('include_path')"],
        'ldap_control_paged_result_response' => ['replacement' => null],
        'ldap_control_paged_result' => ['replacement' => null],
        'mhash'              => ['replacement' => 'hash'],
        'mhash_keygen_s2k'   => ['replacement' => 'hash_pbkdf2'],
        'mysqli_get_client_info' => ['replacement' => 'mysqli_get_client_version'],
        'mysqli_init'             => ['replacement' => '__construct'],
        'odbc_result_all'         => ['replacement' => null],
        'key'                     => ['replacement' => 'array_key_first'],
        'current'                 => ['replacement' => 'current'],
        'next'                    => ['replacement' => 'next'],
        'prev'                    => ['replacement' => 'prev'],
        'reset'                   => ['replacement' => 'reset'],
        'end'                     => ['replacement' => 'end'],
        'xml_set_object'          => ['replacement' => null],

        // Deprecated SAPIs
        'apache'        => ['replacement' => null],
        'apache_hooks'  => ['replacement' => null],
        'apache2filter' => ['replacement' => null],
        'cgi'           => ['replacement' => null],
        'fastcgi'       => ['replacement' => null],
        'isapi'         => ['replacement' => null],
        'nsapi'         => ['replacement' => null],
        'pwsapi'        => ['replacement' => null],

        // Removed Extensions
        'mssql extension' => ['replacement' => 'pdo_mssql'],
        'sybase_ct'       => ['replacement' => 'pdo_sybase'],
        'mcrypt'          => ['replacement' => 'OpenSSL or sodium'],
        'MDB2'            => ['replacement' => null],
        'Ming'            => ['replacement' => null],
        'Phar Data'       => ['replacement' => null],
        'SNMP'            => ['replacement' => null],
        'Tidy'            => ['replacement' => null],
    ];
}

/**
 * For interactive or automatic selection of DB connection variables
 * if multiple are discovered.
 */
function pickConnectionVar(array $connections, Logger $logger): string
{
    if (count($connections) === 0) {
        $logger->warning("No known DB connection found; using \$connection fallback.");
        return 'connection';
    }
    if (count($connections) === 1) {
        $var = reset($connections);
        $logger->info("Using single connection variable '\${$var}'.");
        return $var;
    }

    // Interactive
    $logger->info("Multiple DB connections found: " . implode(', ', $connections));
    echo "\nSelect from multiple DB connection variables:\n";
    foreach ($connections as $i => $connVar) {
        echo "  " . ($i + 1) . ") \${$connVar}\n";
    }
    do {
        $choice = (int) readline("Enter number [1.." . count($connections) . "]: ");
    } while ($choice < 1 || $choice > count($connections));

    $selected = $connections[$choice - 1];
    echo "Using \${$selected}\n";
    $logger->info("User selected \${$selected} for mysqli_query.");
    return $selected;
}

/**
 * Detects DB connections ($conn = mysql_connect/ mysqli_connect)
 * and simple string assignments for usage in rewriting patterns, etc.
 */
class HeuristicScanVisitor extends NodeVisitorAbstract
{
    public $connections = [];
    public $stringVars  = [];

    public function enterNode(Node $node)
    {
        if ($node instanceof Assign && $node->var instanceof Variable) {
            $varName = $node->var->name;
            if ($node->expr instanceof Node\Expr\FuncCall && $node->expr->name instanceof Node\Name) {
                $fnName = $node->expr->name->toString();
                if (in_array($fnName, ['mysql_connect','mysqli_connect'], true)) {
                    $this->connections[] = $varName;
                }
            } elseif ($node->expr instanceof String_) {
                // $var = "someRegex" or something
                $this->stringVars[$varName] = $node->expr->value;
            }
        }
    }
}

/**
 * Replaces deprecated functions after scanning for DB connections, stringVars,
 * with optional rewriting of assert() calls if requested.
 */
class DeprecatedFunctionReplacer extends NodeVisitorAbstract
{
    private $logger;
    private $rules;
    private $analysis;
    private $rewriteAssert;
    private $replacementCount = 0;
    private $warningCount     = 0;

    public function __construct(Logger $logger, array $analysis, array $customRules = [], bool $rewriteAssert = false)
    {
        $this->logger      = $logger;
        $this->analysis    = $analysis;
        $this->rewriteAssert = $rewriteAssert;
        $merged = array_replace_recursive(getDeprecatedRules(), $customRules);
        $this->rules       = $merged;
    }

    public function enterNode(Node $node)
    {
        if ($this->rewriteAssert && $node instanceof Node\Expr\FuncCall) {
            // Convert assert($expr) => if(!($expr)) { throw new \AssertionError("Assertion failed: ..."); }
            if ($node->name instanceof Node\Name && $node->name->toString() === 'assert') {
                if (!empty($node->args)) {
                    $expr = $node->args[0]->value;
                    return new Node\Stmt\If_(
                        new Node\Expr\BooleanNot($expr),
                        [
                            'stmts' => [
                                new Node\Stmt\Throw_(
                                    new Node\Expr\New_(
                                        new Node\Name('\AssertionError'),
                                        [
                                            new Arg(
                                                new String_("Assertion failed: " . $this->exprToString($expr))
                                            )
                                        ]
                                    )
                                )
                            ]
                        ]
                    );
                }
            }
        }

        // Normal deprecated function replacements
        if ($node instanceof Node\Expr\FuncCall && $node->name instanceof Node\Name) {
            $oldName = $node->name->toString();
            if (isset($this->rules[$oldName])) {
                $map         = $this->rules[$oldName];
                $replacement = $map['replacement'] ?? null;
                $rewriteArgs = $map['rewriteArgs']  ?? null;

                if ($replacement) {
                    $this->logger->info("Replacing function: $oldName → $replacement");
                    $node->name = new Node\Name($replacement);
                    $this->replacementCount++;

                    if (is_callable($rewriteArgs)) {
                        $rewriteArgs($node, $this->logger, $this->analysis);
                    }
                } else {
                    $this->logger->warning("Function $oldName is deprecated and has no direct replacement.");
                    $this->warningCount++;
                }
            }
        }
        return null;
    }

    private function exprToString(Node $expr): string
    {
        // naive: variable, property fetch, etc.
        if ($expr instanceof Variable) {
            return '$' . $expr->name;
        } elseif ($expr instanceof PropertyFetch) {
            return '$' . $expr->var->name . '->' . $expr->name->name;
        }
        return 'expression';
    }

    public function getReplacementCount(): int
    {
        return $this->replacementCount;
    }
    public function getWarningCount(): int
    {
        return $this->warningCount;
    }
}

/**
 * Inject type hints from docblocks if --add-docblock-types is set.
 * Naive approach for single-type @param and @return tags.
 */
class DocBlockTypeHintVisitor extends NodeVisitorAbstract
{
    private $logger;
    private $targetVersion;

    private $paramPattern = '/@param\s+([\w\|\\\\\[\]]+)\s+\$(\w+)/';
    private $returnPattern= '/@return\s+([\w\|\\\\\[\]]+)/';

    public function __construct(Logger $logger, string $targetVersion)
    {
        $this->logger = $logger;
        $this->targetVersion = $targetVersion;
    }

    public function enterNode(Node $node)
    {
        if (!($node instanceof Function_ || $node instanceof ClassMethod)) {
            return null;
        }
        $docComment = $node->getDocComment();
        if (!$docComment) {
            return null;
        }
        $text = $docComment->getText();

        // parse param tags
        preg_match_all($this->paramPattern, $text, $paramMatches, PREG_SET_ORDER);

        // parse return tag
        $returnTypeStr = '';
        if (preg_match($this->returnPattern, $text, $ret)) {
            $returnTypeStr = $ret[1] ?? '';
        }

        // param type injection
        if ($paramMatches) {
            foreach ($paramMatches as $pm) {
                $docType  = trim($pm[1]);
                $docVar   = trim($pm[2]);
                foreach ($node->params as $param) {
                    if ($param->var->name === $docVar && $param->type === null) {
                        $cleanType = $this->mapDocBlockType($docType);
                        if ($cleanType !== '') {
                            $param->type = new Node\Name($cleanType);
                            $this->logger->info("Setting param \${$docVar} type to '{$cleanType}' from docblock.");
                        }
                    }
                }
            }
        }

        // return type injection
        if ($returnTypeStr && $node->getReturnType() === null) {
            $cleanType = $this->mapDocBlockType($returnTypeStr);
            if ($cleanType !== '') {
                $node->returnType = new Node\Name($cleanType);
                $this->logger->info("Setting return type to '{$cleanType}' from docblock.");
                return null;
            }
        }

        // If no return type and we can set void for 7.1+ if no return statements
        if ($node->getReturnType() === null &&
            version_compare($this->targetVersion, '7.1', '>=') &&
            !$this->functionHasReturn($node)) {
            $node->returnType = new Node\Identifier('void');
            $this->logger->info("Setting return type to 'void' (no return found, 7.1+).");
        }

        return null;
    }

    private function mapDocBlockType(string $typeStr): string
    {
        if (strpos($typeStr, '|') !== false) {
            return '';
        }
        $typeStr = ltrim($typeStr, '\\');
        switch (strtolower($typeStr)) {
            case 'boolean': return 'bool';
            case 'integer': return 'int';
            case 'double':  return 'float';
            // if it's 'bool', 'int', 'string', 'float', or a single identifier
            default:
                if (preg_match('/^[a-zA-Z_]\w*$/', $typeStr)) {
                    return $typeStr;
                }
                return '';
        }
    }

    private function functionHasReturn($node): bool
    {
        if (!isset($node->stmts)) {
            return false;
        }
        foreach ($node->stmts as $stmt) {
            if ($stmt instanceof Node\Stmt\Return_) {
                return true;
            }
        }
        return false;
    }
}

/**
 * Warn about dynamic properties if they are used in a class
 * but not declared. Since 8.2, this is deprecated.
 */
class DynamicPropertyVisitor extends NodeVisitorAbstract
{
    private $logger;
    private $targetVersion;
    private $classProperties = []; // className => [propName => true]
    private $currentClass = null;

    public function __construct(Logger $logger, string $targetVersion)
    {
        $this->logger = $logger;
        $this->targetVersion = $targetVersion;
    }

    public function enterNode(Node $node)
    {
        if ($node instanceof Node\Stmt\Class_ && isset($node->name)) {
            $this->currentClass = $node->name->name;
            $this->classProperties[$this->currentClass] = [];
            foreach ($node->getProperties() as $pStmt) {
                foreach ($pStmt->props as $p) {
                    $this->classProperties[$this->currentClass][$p->name->toString()] = true;
                }
            }
        }

        if ($node instanceof Assign && $node->var instanceof PropertyFetch) {
            $pf = $node->var;
            if ($pf->var instanceof Variable && $pf->var->name === 'this' && $this->currentClass) {
                $propName = $pf->name->name ?? null;
                if ($propName && !isset($this->classProperties[$this->currentClass][$propName])) {
                    $msg = "Dynamic property \${$propName} in class {$this->currentClass} not declared.";
                    if (version_compare($this->targetVersion, '8.2', '>=')) {
                        $msg .= " (Deprecated in PHP 8.2+)";
                    }
                    $this->logger->warning($msg);
                }
            }
        }
    }

    public function leaveNode(Node $node)
    {
        if ($node instanceof Node\Stmt\Class_ && isset($node->name)) {
            $this->currentClass = null;
        }
    }
}

/**
 * Converts array() => [] if --short-array is used.
 */
class ShortArrayVisitor extends NodeVisitorAbstract
{
    private $logger;
    private $convertedCount = 0;

    public function __construct(Logger $logger)
    {
        $this->logger = $logger;
    }

    public function enterNode(Node $node)
    {
        if ($node instanceof Node\Expr\Array_) {
            if (!$node->hasAttribute('kind') || $node->getAttribute('kind') === Node\Expr\Array_::KIND_LONG) {
                $node->setAttribute('kind', Node\Expr\Array_::KIND_SHORT);
                $this->convertedCount++;
            }
        }
        return null;
    }

    public function getConvertedCount(): int
    {
        return $this->convertedCount;
    }
}

/**
 * Inserts declare(strict_types=1); at the top if missing.
 */
function ensureStrictTypes(string $code): string
{
    if (!preg_match('/declare\s*\(\s*strict_types\s*=\s*1\s*\)\s*;\s*/', $code)) {
        return "<?php\ndeclare(strict_types=1);\n\n" . preg_replace('/^<\?php\s*/', '', $code, 1);
    }
    return $code;
}

/**
 * Warn if short tags are present but short_open_tag=off.
 */
function detectShortTags(string $code, Logger $logger): void
{
    if (ini_get('short_open_tag') !== '1') {
        if (preg_match('/<\?[^ph]/', $code)) {
            $logger->warning("Short tags detected but short_open_tag is disabled. Consider removing them or enabling short_open_tag.");
        }
    }
}

/**
 * Check for known deprecated INI directives in a php.ini file.
 */
function detectDeprecatedIniDirectives(string $iniFilePath, Logger $logger): void
{
    $deprecated = [
        'define_syslog_variables',
        'register_globals',
        'register_long_arrays',
        'safe_mode',
        'magic_quotes_gpc',
        'magic_quotes_runtime',
        'magic_quotes_sybase',
        'session.entropy_file',
        'session.entropy_length',
        'session.hash_function',
        'session.hash_bits_per_character',
        'asp_tags',
        'y2k_compliance',
        'auto_detect_line_endings',
        'session.use_trans_sid',
        'session.use_only_cookies',
        'session.trans_sid_tags',
        'oci8.old_oci_close_semantics',
    ];

    if (!file_exists($iniFilePath)) {
        $logger->error("INI file not found: $iniFilePath");
        return;
    }
    $content = file_get_contents($iniFilePath);
    if ($content === false) {
        $logger->error("Failed to read INI file: $iniFilePath");
        return;
    }
    foreach ($deprecated as $d) {
        if (preg_match("/^\s*" . preg_quote($d, '/') . "\s*=/m", $content)) {
            $logger->warning("Deprecated INI directive found: $d in $iniFilePath");
        }
    }
}

/**
 * Main migration pipeline combining:
 *  1) DocBlock-based type hint insertion (optional),
 *  2) Heuristic scanning for DB connections & pattern strings,
 *  3) Replacing deprecated functions,
 *  4) Dynamic property detection,
 *  5) Short array syntax conversion (optional),
 *  6) Insert strict_types, short-tag detection, final logging.
 */
function migratePhpCode(
    string $source,
    Logger $logger,
    bool $useShortArray,
    bool $rewriteAssert,
    bool $addDocblockTypes,
    string $targetVersion,
    array $customRules = []
): ?string {
    $parser  = (new ParserFactory())->create(ParserFactory::PREFER_PHP7);
    $printer = new Standard();

    try {
        $ast = $parser->parse($source);
        if (!$ast) {
            $logger->error("Parser returned null AST—possible parse error or empty file.");
            return null;
        }

        // 1) Docblock param/return injection if requested
        if ($addDocblockTypes) {
            $docTraverser = new NodeTraverser();
            $docTraverser->addVisitor(new DocBlockTypeHintVisitor($logger, $targetVersion));
            $ast = $docTraverser->traverse($ast);
        }

        // 2) Heuristic scan
        $scanTraverser = new NodeTraverser();
        $scanVisitor = new HeuristicScanVisitor();
        $scanTraverser->addVisitor($scanVisitor);
        $scanTraverser->traverse($ast);

        // 3) Replace deprecated
        $replaceTraverser = new NodeTraverser();
        $deprecatedVisitor = new DeprecatedFunctionReplacer(
            $logger,
            [
                'connections' => $scanVisitor->connections,
                'stringVars'  => $scanVisitor->stringVars,
            ],
            $customRules,
            $rewriteAssert
        );
        $replaceTraverser->addVisitor($deprecatedVisitor);
        $ast = $replaceTraverser->traverse($ast);

        // 4) Dynamic property detection
        $dynTraverser = new NodeTraverser();
        $dynVisitor = new DynamicPropertyVisitor($logger, $targetVersion);
        $dynTraverser->addVisitor($dynVisitor);
        $ast = $dynTraverser->traverse($ast);

        // 5) Short array if needed
        if ($useShortArray) {
            $shortTraverser = new NodeTraverser();
            $shortVisitor   = new ShortArrayVisitor($logger);
            $shortTraverser->addVisitor($shortVisitor);
            $ast = $shortTraverser->traverse($ast);
            $logger->info("Converted {$shortVisitor->getConvertedCount()} array() calls to [] syntax.");
        }

        // Generate final code
        $code = $printer->prettyPrintFile($ast);

        // Insert strict_types
        $code = ensureStrictTypes($code);

        // Detect short tags
        detectShortTags($code, $logger);

        // Log replaced/warning stats
        $logger->info("Replaced {$deprecatedVisitor->getReplacementCount()} deprecated calls.");
        $logger->info("Warnings: {$deprecatedVisitor->getWarningCount()}");

        return $code;
    } catch (Error $e) {
        $logger->error("Error parsing code: " . $e->getMessage());
        return null;
    }
}

/**
 * Process either a single file or all .php files in a directory.
 */
function processPhpFiles(
    string $inputPath,
    string $outputDir,
    Logger $logger,
    bool $useShortArray,
    bool $rewriteAssert,
    bool $addDocblockTypes,
    string $targetVersion,
    bool $backup,
    array $customRules
): void {
    if (is_file($inputPath)) {
        processPhpFile(
            $inputPath,
            $outputDir,
            $logger,
            $useShortArray,
            $rewriteAssert,
            $addDocblockTypes,
            $targetVersion,
            $backup,
            $customRules
        );
    } elseif (is_dir($inputPath)) {
        $files = glob(rtrim($inputPath, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . '*.php');
        foreach ($files as $file) {
            processPhpFile(
                $file,
                $outputDir,
                $logger,
                $useShortArray,
                $rewriteAssert,
                $addDocblockTypes,
                $targetVersion,
                $backup,
                $customRules
            );
        }
    } else {
        $logger->error("Invalid input path: $inputPath");
    }
}

/**
 * Process a single file, optionally backing it up, migrating code, saving.
 */
function processPhpFile(
    string $filePath,
    string $outputDir,
    Logger $logger,
    bool $useShortArray,
    bool $rewriteAssert,
    bool $addDocblockTypes,
    string $targetVersion,
    bool $backup,
    array $customRules
): void {
    try {
        if (!file_exists($filePath)) {
            throw new \RuntimeException("File not found: $filePath");
        }
        $source = file_get_contents($filePath);
        if ($source === false) {
            throw new \RuntimeException("Failed reading file: $filePath");
        }

        $logger->info("Processing file: $filePath");
        $migrated = migratePhpCode(
            $source,
            $logger,
            $useShortArray,
            $rewriteAssert,
            $addDocblockTypes,
            $targetVersion,
            $customRules
        );
        if ($migrated) {
            if (!is_dir($outputDir)) {
                if (!mkdir($outputDir, 0755, true) && !is_dir($outputDir)) {
                    throw new \RuntimeException("Failed creating output directory: $outputDir");
                }
            }
            $outPath = rtrim($outputDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . basename($filePath);

            if ($backup) {
                $bakPath = $outPath . '.bak';
                if (!copy($filePath, $bakPath)) {
                    throw new \RuntimeException("Failed to backup original file to: $bakPath");
                }
                $logger->info("Backup created at $bakPath");
            }

            if (file_put_contents($outPath, $migrated) === false) {
                throw new \RuntimeException("Failed writing migrated code to: $outPath");
            }
            $logger->info("Migrated file saved.", ['outputPath' => $outPath]);
        }
    } catch (\Exception $e) {
        $logger->error("Error processing file: " . $e->getMessage(), [
            'filePath' => $filePath
        ]);
    }
}

/**
 * Runs static analysis with PHPStan (level 8).
 */
function runStaticAnalysis(string $outputDir, Logger $logger): void
{
    $phpstanBin = __DIR__ . '/vendor/bin/phpstan';
    $level      = 8;

    if (is_dir($outputDir)) {
        $cmd = "$phpstanBin analyse $outputDir --level=$level";
        $proc = new Process(explode(' ', $cmd));
        $proc->run();
        if ($proc->isSuccessful()) {
            $logger->info("Static analysis completed successfully.", ['output' => $proc->getOutput()]);
        } else {
            $logger->error("Static analysis failed.", ['output' => $proc->getErrorOutput()]);
        }
    } else {
        $logger->error("Output directory not found for static analysis: $outputDir");
    }
}

/**
 * Runs PHPUnit tests (if installed).
 */
function runUnitTests(Logger $logger): void
{
    $phpunitBin = __DIR__ . '/vendor/bin/phpunit';
    $proc = new Process([$phpunitBin]);
    $proc->run();
    if ($proc->isSuccessful()) {
        $logger->info("Unit tests passed.", ['output' => $proc->getOutput()]);
    } else {
        $logger->error("Unit tests failed.", ['output' => $proc->getErrorOutput()]);
    }
}

/******************************************************
 * MAIN CLI ENTRY
 ******************************************************/
$logger = new Logger('PHPCodeMigrator');
$logger->pushHandler(new StreamHandler(__DIR__ . '/migration.log', Logger::DEBUG));

// CLI options
$options = getopt(
    "i:o:c:I:",
    [
        "input:",
        "output:",
        "custom-rules:",
        "ini-file:",
        "short-array",
        "backup",
        "fix-style",
        "non-interactive",
        "rewrite-assert",
        "add-docblock-types",
        "target-version:",
    ]
);

$inputPath       = $options['i']            ?? $options['input']         ?? null;
$outputDir       = $options['o']            ?? $options['output']        ?? (__DIR__ . '/migrated');
$customRulesPath = $options['c']            ?? $options['custom-rules']  ?? null;
$iniFilePath     = $options['I']            ?? $options['ini-file']      ?? null;

$useShortArray    = isset($options['short-array']);
$backup           = isset($options['backup']);
$fixStyle         = isset($options['fix-style']);
$nonInteractive   = isset($options['non-interactive']);
$rewriteAssert    = isset($options['rewrite-assert']);
$addDocblockTypes = isset($options['add-docblock-types']);
$targetVersion    = $options['target-version'] ?? '7.4';

$customRules = [];
if ($customRulesPath && file_exists($customRulesPath)) {
    $data = file_get_contents($customRulesPath);
    if ($data !== false) {
        $decoded = json_decode($data, true);
        if (is_array($decoded)) {
            $customRules = $decoded;
            $logger->info("Loaded custom rules from: $customRulesPath");
        }
    }
}

// If --non-interactive, override pickConnectionVar
if ($nonInteractive) {
    $logger->info("Non-interactive mode: picking the last connection variable if multiple are found.");
    function pickConnectionVar(array $connections, Logger $logger): string {
        if (count($connections) === 0) {
            $logger->warning("No known DB connection; using \$connection fallback.");
            return 'connection';
        }
        if (count($connections) === 1) {
            $logger->info("Using single DB connection: \${$connections[0]}");
            return $connections[0];
        }
        $last = end($connections);
        $logger->info("Multiple DB connections found; picking \${$last} non-interactively.");
        return $last;
    }
}

// Check for deprecated INI directives
if ($iniFilePath) {
    detectDeprecatedIniDirectives($iniFilePath, $logger);
}

// Process input (file or directory)
if (!$inputPath) {
    $logger->error("No input path provided. Use -i or --input to specify a file or directory.");
    exit(1);
}
processPhpFiles($inputPath, $outputDir, $logger,
    $useShortArray, $rewriteAssert, $addDocblockTypes, $targetVersion,
    $backup, $customRules
);

// Static analysis
runStaticAnalysis($outputDir, $logger);

// Optionally fix style
if ($fixStyle) {
    $styleCmd = ['vendor/bin/php-cs-fixer', 'fix', $outputDir];
    $logger->info("Running style fix: " . implode(' ', $styleCmd));
    $p = new Process($styleCmd);
    $p->run();
    if ($p->isSuccessful()) {
        $logger->info("Style fixing completed.", ['output' => $p->getOutput()]);
    } else {
        $logger->warning("Style fixing might have failed or is not installed.", ['output' => $p->getErrorOutput()]);
    }
}

// Run unit tests
runUnitTests($logger);

$logger->info("Migration process completed.");
