#!/usr/bin/env python3
"""Install sonar-cryptography (CBOMkit, C/C++ PR #377) + SonarQube and run CBOM experiments on Vanetza.

Writes results/<experiment>/cbom.json, results/evidence.csv and results/comparison.md.

Location: <vanetza>/cbom/sonar-cryptography/run.py
Usage:    ./run.py [all|setup|experiments]        (default: all)
Env vars: SONAR_ADMIN_PASSWORD  (else prompted, never stored)
          INSTALL_DEPS=1        apt-install missing tools and headers (needs sudo)
          ONLY=E1-baseline,E2-openssl111   run a subset of the experiments
          REBUILD=1             rebuild the plugin   NO_COLOR=1   plain output
"""
import atexit
import getpass
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from base64 import b64encode
from dataclasses import dataclass
from pathlib import Path

# ----------------------------------------------------------------------------- settings
HERE = Path(__file__).resolve().parent
VANETZA_ROOT = Path(os.environ.get("VANETZA_ROOT", HERE.parent.parent))
WORK_DIR = Path(os.environ.get("WORK_DIR", HERE / "work"))
RESULTS_DIR = Path(os.environ.get("RESULTS_DIR", HERE / "results"))
LOG_DIR = WORK_DIR / "logs"
PLUGIN_DIR = WORK_DIR / "sonar-cryptography"

PLUGIN_REPO = "https://github.com/cbomkit/sonar-cryptography.git"
PLUGIN_PR = 377
PLUGIN_COMMIT = "d64072f"  # pinned for reproducibility
SONAR_URL = os.environ.get("SONAR_HOST", "http://localhost:9000")
SONAR_USER = "admin"
SCANNER_VERSION = "8.5.0.16571"
SCANNER_DIR = WORK_DIR / f"sonar-scanner-cli-{SCANNER_VERSION}"
QUALITY_PROFILE = "Cryptography"
RULE_KEY = "sonar-cpp-crypto:Inventory"

SCAN_SOURCES = "vanetza/security,tools/certify,tools/socktap"
SCAN_EXCLUSIONS = "vanetza/asn1/**"  # not under the sources above; a safeguard if you widen them
FILE_SUFFIXES = ".c,.cc,.cpp,.cxx,.c++,.h,.hh,.hpp,.hxx,.h++"


@dataclass
class Experiment:
    name: str
    defines: list  # become sonar.cxx.defines (the analyzer runs a C preprocessor)
    description: str
    only: list = None  # optional file patterns (sonar.inclusions) that narrow the scan


OPENSSL = "VANETZA_WITH_OPENSSL 1"
CRYPTOPP = "VANETZA_WITH_CRYPTOPP 1"
COMPAT_111 = "OPENSSL_API_COMPAT 0x10101000L"  # OpenSSL 1.1.1 code paths (what the Docker image builds)
COMPAT_10 = "OPENSSL_API_COMPAT 0x10000000L"   # legacy OpenSSL 1.0 code paths

OPENSSL_FILES = ["vanetza/security/backend_openssl.*", "vanetza/security/sha.cpp"]
CRYPTOPP_FILES = ["vanetza/security/backend_cryptopp.*", "vanetza/security/persistence.*",
                  "vanetza/security/sha.cpp", "tools/certify/**"]

# Each experiment answers one question. Full-scope scans take ~10 minutes, narrow ones should be quicker.
EXPERIMENTS = [
    Experiment("E1-full-baseline", [OPENSSL, CRYPTOPP, COMPAT_111],
               "Full scope, realistic build config. The reference result."),
    Experiment("E2-full-cryptopp-defines", [CRYPTOPP],
               "Full scope, only Crypto++ defined. Does the preprocessor config change the CBOM?"),
    Experiment("E3-cryptopp-files-only", [CRYPTOPP],
               "Only the Crypto++ files. Expect nothing: the plugin has no Crypto++ rules.", CRYPTOPP_FILES),
    Experiment("E4-openssl-files-only", [OPENSSL, COMPAT_111],
               "Only the OpenSSL files. Does a narrow scan match the full one (and is it faster)?", OPENSSL_FILES),
    Experiment("E5-openssl-files-legacy", [OPENSSL, COMPAT_10],
               "Only the OpenSSL files, OpenSSL 1.0 code paths. Does OPENSSL_API_COMPAT matter?", OPENSSL_FILES),
]
if os.environ.get("ONLY"):
    wanted = os.environ["ONLY"].split(",")
    unknown = [w for w in wanted if w not in [e.name for e in EXPERIMENTS]]
    if unknown:
        sys.exit(f"ONLY: unknown experiment(s): {', '.join(unknown)}")
    EXPERIMENTS = [e for e in EXPERIMENTS if e.name in wanted]

# ----------------------------------------------------------------------------- output helpers
TTY = sys.stdout.isatty()
COLOR = TTY and not os.environ.get("NO_COLOR")
UTF8 = (sys.stdout.encoding or "").lower().startswith("utf")
OK, BAD, WARN, DOT, RULE = ("✔", "✘", "▲", "•", "━") if UTF8 else ("+", "x", "!", "*", "=")
FULL, EMPTY = ("█", "░") if UTF8 else ("#", "-")
SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏" if UTF8 else "|/-\\"
WIDTH = shutil.get_terminal_size().columns


def style(code, text):
    return f"\033[{code}m{text}\033[0m" if COLOR else text


bold = lambda t: style("1", t)
dim = lambda t: style("2", t)
green = lambda t: style("32", t)
yellow = lambda t: style("33", t)
red = lambda t: style("31", t)
cyan = lambda t: style("36", t)


def bar(done, total, width=28):
    filled = min(width, done * width // max(total, 1))
    return FULL * filled + EMPTY * (width - filled)


def duration(seconds):
    seconds = int(seconds)
    return f"{seconds // 60}m{seconds % 60:02d}s" if seconds >= 60 else f"{seconds}s"


class Fail(Exception):
    """A step failed; the message is shown to the user and the run stops."""


class Steps:
    """Numbered step headers with an overall progress bar."""

    def __init__(self, total):
        self.total, self.current = total, 0

    def start(self, title):
        percent = self.current * 100 // self.total
        print(f"\n{cyan(RULE * 2)} {bold(f'[{self.current + 1}/{self.total}] {title}')}")
        print(f"   {dim('overall')} {bar(self.current, self.total)} {dim(f'{percent}%')}")
        self.current += 1


def ok(text):
    print(f"   {green(OK)} {text}")


def info(text):
    print(f"   {dim(DOT + ' ' + text)}")


def warn(text):
    print(f"   {yellow(WARN)} {yellow(text)}", file=sys.stderr)


if TTY:  # always bring the cursor back
    atexit.register(lambda: print("\033[?25h", end=""))


def spinner_line(label, started, status=""):
    frame = SPINNER[int((time.time() - started) * 10) % len(SPINNER)]
    room = max(10, WIDTH - len(label) - 18)
    print(f"\r\033[K   {cyan(frame)} {label}  {dim(duration(time.time() - started))}  {dim(status[:room])}", end="", flush=True)


# ----------------------------------------------------------------------------- running commands
def last_line(log):
    """Status text: the last non-empty line of a log file."""
    text = log.read_text(errors="replace").replace("\r", "\n")
    text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text)
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    return lines[-1] if lines else ""


def maven_status(log):
    """Status text for Maven: a bar from its '[3/13]' module counter."""
    found = re.findall(r"\[INFO\] Building (\S+) .*\[\s*(\d+)/(\d+)\]", log.read_text(errors="replace"))
    if not found:
        return last_line(log)
    name, current, total = found[-1][0], int(found[-1][1]), int(found[-1][2])
    return f"{bar(current - 1, total, 18)} {current}/{total} {name}"


def scanner_status(log):
    return re.sub(r"^[\d:.]+ +(INFO|WARN|ERROR|DEBUG):? +", "", last_line(log))


log_count = 0


def run_task(label, cmd, cwd=None, env=None, status=last_line, must_succeed=True):
    """Run a command with a spinner. Its output goes to a log file. Returns (ok, log_path)."""
    global log_count
    log_count += 1
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log = LOG_DIR / f"{log_count:02d}-{re.sub(r'[^A-Za-z0-9]+', '_', label)}.log"
    started = time.time()
    if TTY:
        print("\033[?25l", end="")
    else:
        info(f"{label} ...")
    with open(log, "wb") as out:
        try:
            proc = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=out, stderr=subprocess.STDOUT)
        except FileNotFoundError:
            raise Fail(f"{label}: command not found: {cmd[0]}")
        try:
            while proc.poll() is None:
                if TTY:
                    spinner_line(label, started, status(log))
                time.sleep(0.1)
        except BaseException:
            proc.terminate()
            raise
    if TTY:
        print("\r\033[K\033[?25h", end="")
    elapsed = duration(time.time() - started)
    if proc.returncode == 0:
        ok(f"{label}  {dim('(' + elapsed + ')')}")
        return True, log
    print(f"   {red(BAD)} {label}  {dim('(failed after ' + elapsed + ')')}", file=sys.stderr)
    for line in log.read_text(errors="replace").splitlines()[-12:]:
        print(f"       | {line}", file=sys.stderr)
    print(f"     full log: {log}", file=sys.stderr)
    if must_succeed:
        raise Fail(f"{label} failed")
    return False, log


def wait_until(label, is_ready, timeout=360):
    """Poll is_ready() with a spinner (used while SonarQube starts)."""
    started = time.time()
    while time.time() - started < timeout:
        if is_ready():
            ok(f"{label}  {dim('(' + duration(time.time() - started) + ')')}")
            return
        if TTY:
            spinner_line(label, started)
        time.sleep(1 if not TTY else 0.2)
    raise Fail(f"{label}: timed out after {duration(timeout)}")


# ----------------------------------------------------------------------------- SonarQube API
class SonarQube:
    def __init__(self):
        self.password = os.environ.get("SONAR_ADMIN_PASSWORD", "admin")

    def call(self, method, path, **params):
        """Call the web API. Returns (http_status, parsed_json). Status 0 = not reachable."""
        query = urllib.parse.urlencode(params)
        url = SONAR_URL + path + (f"?{query}" if method == "GET" and query else "")
        body = query.encode() if method != "GET" else None
        request = urllib.request.Request(url, data=body, method=method)
        request.add_header("Authorization", "Basic " + b64encode(f"{SONAR_USER}:{self.password}".encode()).decode())
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                code, text = response.status, response.read().decode()
        except urllib.error.HTTPError as error:
            code, text = error.code, error.read().decode()
        except OSError:
            return 0, {}
        try:
            return code, json.loads(text) if text else {}
        except ValueError:
            return code, {}

    def server_status(self):
        return self.call("GET", "/api/system/status")[1]

    def is_up(self):
        return self.server_status().get("status") == "UP"

    def login(self):
        """Check the admin password; ask for it if the default is wrong."""
        code, _ = self.call("GET", "/api/users/search", q=SONAR_USER)
        if code == 401:
            if not sys.stdin.isatty():
                raise Fail("SonarQube rejected the admin password (set SONAR_ADMIN_PASSWORD)")
            self.password = getpass.getpass(f"   ? SonarQube admin password for '{SONAR_USER}': ")
            code, _ = self.call("GET", "/api/users/search", q=SONAR_USER)
        if code != 200:
            raise Fail(f"cannot authenticate to SonarQube (HTTP {code})")

    def ensure_profile(self):
        """Create the C/C++ quality profile with the Inventory rule active."""
        _, found = self.call("GET", "/api/qualityprofiles/search", language="cxx", qualityProfile=QUALITY_PROFILE)
        keys = [p["key"] for p in found.get("profiles", []) if p["name"] == QUALITY_PROFILE]
        if keys:
            key = keys[0]
        else:
            code, created = self.call("POST", "/api/qualityprofiles/create", language="cxx", name=QUALITY_PROFILE)
            if code != 200:
                raise Fail(f"could not create quality profile (HTTP {code})")
            key = created["profile"]["key"]
        code, _ = self.call("POST", "/api/qualityprofiles/activate_rule", key=key, rule=RULE_KEY)
        if code not in (200, 204):
            raise Fail(f"could not activate {RULE_KEY} (HTTP {code})")
        return key


# ----------------------------------------------------------------------------- setup steps
def check_prerequisites():
    install = os.environ.get("INSTALL_DEPS") == "1"
    tools = {"git": "git", "unzip": "unzip", "java": "openjdk-21-jdk", "mvn": "maven"}
    packages = [pkg for cmd, pkg in tools.items() if not shutil.which(cmd)]
    if not Path("/usr/include/openssl").is_dir() or not Path("/usr/include/cryptopp").is_dir():
        packages += ["libssl-dev", "libcrypto++-dev"]  # headers the analyzer needs

    if packages and install:
        subprocess.run(["sudo", "-v"], check=True)  # ask for the sudo password up front
        run_task("Updating package lists", ["sudo", "-n", "apt-get", "update"])
        run_task("Installing " + " ".join(packages),
                 ["sudo", "-n", "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "-y", *packages])
    elif packages:
        warn("missing: " + " ".join(packages) + "  (INSTALL_DEPS=1 installs them with apt)")

    if not shutil.which("docker"):
        raise Fail("Docker is not installed (install Docker Engine + the Compose plugin)")
    problems = [c for c in ("git", "java", "mvn") if not shutil.which(c)]
    if problems:
        raise Fail(f"missing: {', '.join(problems)}  (run with INSTALL_DEPS=1)")

    version = subprocess.run(["java", "-version"], capture_output=True, text=True).stderr
    major = int(re.search(r'version "(\d+)', version).group(1))
    if major < 21:
        raise Fail(f"Java 21+ is required, found {major}. Install openjdk-21-jdk and set JAVA_HOME.")
    if subprocess.run(["docker", "compose", "version"], capture_output=True).returncode != 0:
        raise Fail("the 'docker compose' plugin is missing")
    if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
        raise Fail("cannot reach the Docker daemon (is it running? are you in the docker group?)")
    if not (VANETZA_ROOT / "vanetza" / "security").is_dir():
        raise Fail(f"{VANETZA_ROOT} does not look like the Vanetza source tree")
    ok(f"git, java {major}, maven, docker")


def prepare_plugin_source():
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    if not (PLUGIN_DIR / ".git").is_dir():
        run_task("Cloning sonar-cryptography", ["git", "clone", "--progress", PLUGIN_REPO, str(PLUGIN_DIR)])
    run_task(f"Fetching PR #{PLUGIN_PR}", ["git", "fetch", "-f", "origin", f"pull/{PLUGIN_PR}/head:pr-{PLUGIN_PR}"], cwd=PLUGIN_DIR)
    has_commit = subprocess.run(["git", "cat-file", "-e", PLUGIN_COMMIT + "^{commit}"], cwd=PLUGIN_DIR, capture_output=True).returncode == 0
    if not has_commit:
        warn(f"commit {PLUGIN_COMMIT} is no longer in PR #{PLUGIN_PR}; using the PR tip")
    subprocess.run(["git", "checkout", "-q", PLUGIN_COMMIT if has_commit else f"pr-{PLUGIN_PR}"], cwd=PLUGIN_DIR, check=True)
    head = subprocess.run(["git", "log", "-1", "--format=%h  %s"], cwd=PLUGIN_DIR, capture_output=True, text=True).stdout.strip()
    ok(f"checked out {head[:70]}")


def build_plugin():
    plugins = PLUGIN_DIR / ".SonarQube" / "plugins"
    if not list(plugins.glob("*.jar")) or os.environ.get("REBUILD") == "1":
        run_task("Maven build (skip tests)", ["mvn", "-B", "-ntp", "clean", "package", "-DskipTests"], cwd=PLUGIN_DIR, status=maven_status)
    else:
        ok(f"plugin already built {dim('(REBUILD=1 to force)')}")
    if not list(plugins.glob("*.jar")):  # Maven normally copies it; do it by hand if not
        built = [j for j in (PLUGIN_DIR / "sonar-cryptography-plugin" / "target").glob("*.jar")
                 if not j.name.startswith("original-") and not j.name.endswith("-sources.jar")]
        if not built:
            raise Fail(f"no plugin JAR was produced; see the logs in {LOG_DIR}")
        plugins.mkdir(parents=True, exist_ok=True)
        shutil.copy(built[0], plugins)
    ok("plugin: " + next(plugins.glob("*.jar")).name)


def start_sonarqube(sonar):
    compose = ["docker", "compose"]
    if sonar.is_up():
        ok(f"already running at {SONAR_URL}")
    else:
        (PLUGIN_DIR / ".env").write_text(f"UID={os.getuid()}\n")
        run_task("Starting containers (docker compose)", compose + ["up", "-d"], cwd=PLUGIN_DIR)
        wait_until("Waiting for SonarQube", sonar.is_up)
    sonar.login()
    ok(f"logged in as {bold(SONAR_USER)}  {dim('(SonarQube ' + str(sonar.server_status().get('version', '?')) + ')')}")
    if sonar.call("GET", "/api/rules/show", key=RULE_KEY)[0] != 200:
        warn(f"rule {RULE_KEY} not loaded; restarting SonarQube so it picks up the plugin")
        run_task("Restarting SonarQube", compose + ["restart", "sonarqube"], cwd=PLUGIN_DIR)
        wait_until("Waiting for SonarQube", sonar.is_up)
        if sonar.call("GET", "/api/rules/show", key=RULE_KEY)[0] != 200:
            raise Fail(f"rule {RULE_KEY} is still missing; is the JAR in {PLUGIN_DIR}/.SonarQube/plugins/ ?")
    ok(f"rule {bold(RULE_KEY)} available")


def download(url, destination):
    """Download a file with a progress bar."""
    def show(blocks, block_size, total):
        if TTY and total > 0:
            done = min(blocks * block_size, total)
            print(f"\r\033[K   {cyan(DOT)} Downloading  {bar(done, total, 20)} {done * 100 // total}%", end="", flush=True)
    urllib.request.urlretrieve(url, destination, show)
    if TTY:
        print("\r\033[K", end="")


def unpack_scanner(archive, download_dir):
    """Unzip the scanner and move its single top-level folder to SCANNER_DIR.

    The folder name inside the zip differs from the zip's own name, so we do not guess it.
    """
    subprocess.run(["unzip", "-q", str(archive), "-d", str(download_dir)], check=True)  # unzip keeps file permissions
    folders = [p for p in download_dir.iterdir() if p.is_dir()]
    if len(folders) != 1:
        raise Fail(f"unexpected scanner archive layout: {[p.name for p in folders]}")
    shutil.move(str(folders[0]), SCANNER_DIR)


def install_scanner():
    if (SCANNER_DIR / "bin" / "sonar-scanner").exists():
        ok(f"scanner {SCANNER_VERSION} already installed")
        return
    arch = {"aarch64": "linux-aarch64", "arm64": "linux-aarch64", "x86_64": "linux-x64"}.get(platform.machine())
    if not arch:
        raise Fail(f"unsupported CPU: {platform.machine()}")
    name = f"sonar-scanner-cli-{SCANNER_VERSION}-{arch}"
    url = f"https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/{name}.zip"
    download_dir = WORK_DIR / "download"
    shutil.rmtree(download_dir, ignore_errors=True)
    download_dir.mkdir(parents=True)
    archive = download_dir / f"{name}.zip"
    download(url, archive)
    ok(f"downloaded {name}")
    try:  # SonarSource publishes a checksum next to the zip
        expected = urllib.request.urlopen(url + ".sha256", timeout=30).read().decode().split()[0]
    except OSError:
        expected = None
        warn("no checksum published for this download; not verified")
    if expected:
        if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
            raise Fail("scanner checksum mismatch")
        ok("checksum verified")
    unpack_scanner(archive, download_dir)
    shutil.rmtree(download_dir)
    ok(f"installed to {dim(str(SCANNER_DIR))}")


# ----------------------------------------------------------------------------- experiments
def include_dirs():
    """Header search path: the project root, /usr/include and the Debian/Ubuntu multiarch folder."""
    return f".,/usr/include,/usr/include/{platform.machine()}-linux-gnu"


def write_properties(experiment, folder):
    properties = {
        "sonar.projectKey": project_key(experiment),
        "sonar.projectName": f"vanetza {experiment.name}",
        "sonar.sources": SCAN_SOURCES,
        "sonar.exclusions": SCAN_EXCLUSIONS,
        "sonar.cxx.file.suffixes": FILE_SUFFIXES,
        "sonar.cxx.defines": "\\n".join(experiment.defines),  # a literal \n separates defines
        "sonar.cxx.includeDirectories": include_dirs(),
        "sonar.host.url": SONAR_URL,
        "sonar.sourceEncoding": "UTF-8",
    }
    if experiment.only:
        properties["sonar.inclusions"] = ",".join(experiment.only)
    path = folder / "sonar.properties"
    path.write_text("".join(f"{k}={v}\n" for k, v in properties.items()))
    return path


def project_key(experiment):
    return "vanetza-" + experiment.name.lower()


def read_cbom(path):
    """Return the CBOM's assets as [(name, [(file, line, api_call), ...]), ...].

    Files are shown relative to the Vanetza root (the plugin writes absolute paths).
    """
    assets = []
    for component in json.loads(path.read_text()).get("components", []):
        evidence = []
        for o in component.get("evidence", {}).get("occurrences", []):
            file = o.get("location", "?").replace(f"{VANETZA_ROOT}/", "")
            evidence.append((file, o.get("line", 0), o.get("additionalContext", "")))
        assets.append((component.get("name", "?"), sorted(evidence)))
    return assets


def run_experiment(sonar, experiment, token):
    folder = RESULTS_DIR / experiment.name
    shutil.rmtree(folder, ignore_errors=True)
    folder.mkdir(parents=True)
    for pattern in experiment.only or []:
        if not list(VANETZA_ROOT.glob(pattern)):
            raise Fail(f"{experiment.name}: no file matches '{pattern}' under {VANETZA_ROOT}")
    properties = write_properties(experiment, folder)
    info("defines: " + ", ".join(experiment.defines))
    info("files:   " + (", ".join(experiment.only) if experiment.only else "everything in " + SCAN_SOURCES))

    key = project_key(experiment)
    code, _ = sonar.call("POST", "/api/projects/create", project=key, name=f"vanetza {experiment.name}")
    if code not in (200, 400):  # 400 = project already exists
        raise Fail(f"could not create project {key} (HTTP {code})")
    code, _ = sonar.call("POST", "/api/qualityprofiles/add_project", language="cxx", qualityProfile=QUALITY_PROFILE, project=key)
    if code not in (200, 204):
        raise Fail(f"could not attach the quality profile to {key} (HTTP {code})")

    started = time.time()
    scan = [str(SCANNER_DIR / "bin" / "sonar-scanner"),
            f"-Dproject.settings={properties}",
            f"-Dsonar.projectBaseDir={VANETZA_ROOT}",
            f"-Dsonar.working.directory={folder / '.scannerwork'}",
            f"-Dsonar.cryptoScanner.cbom={folder / 'cbom'}"]  # the plugin appends .json
    succeeded, log = run_task("Scanning", scan, cwd=folder, env={**os.environ, "SONAR_TOKEN": token},
                              status=scanner_status, must_succeed=False)
    shutil.copy(log, folder / "scanner.log")

    result = {"name": experiment.name, "seconds": time.time() - started, "assets": [], "description": experiment.description}
    cbom = folder / "cbom.json"
    if not succeeded:
        result.update(state="failed", count="-", locations="-", note=f"see results/{experiment.name}/scanner.log")
    elif cbom.exists():
        assets = read_cbom(cbom)
        locations = sum(len(evidence) for _, evidence in assets)
        result.update(state="ok", count=str(len(assets)), assets=assets, locations=locations,
                      note=", ".join(name for name, _ in assets))
        ok(f"CBOM: {bold(f'{len(assets)} component(s)')}, {locations} evidence location(s)")
        for name, evidence in assets:
            for file, line, api in evidence:
                print(f"       {name:<10} {file}:{line}  {dim(api)}")
    else:
        result.update(state="empty", count="0", locations=0, note="no cryptographic assets detected")
        warn("no CBOM produced (no assets detected)")
    return result


def run_experiments(steps, sonar):
    steps.start("Preparing scan session")
    if not (SCANNER_DIR / "bin" / "sonar-scanner").exists():
        raise Fail("scanner not installed; run: ./run.py setup")
    if not sonar.is_up():
        raise Fail("SonarQube is not running; run: ./run.py setup")
    sonar.login()
    sonar.ensure_profile()
    ok(f"quality profile {bold(QUALITY_PROFILE)} ready")

    token_name = time.strftime("cbom-exp-%Y%m%d%H%M%S")
    code, created = sonar.call("POST", "/api/user_tokens/generate", name=token_name)
    if code != 200:
        raise Fail(f"could not create a scan token (HTTP {code})")
    ok(f"temporary scan token created {dim('(revoked automatically at the end)')}")

    results = []
    try:
        for experiment in EXPERIMENTS:
            steps.start(f"Experiment {bold(experiment.name)} {dim(experiment.description)}")
            results.append(run_experiment(sonar, experiment, created["token"]))
    finally:
        sonar.call("POST", "/api/user_tokens/revoke", name=token_name)
    return results


# ----------------------------------------------------------------------------- summary and main
def evidence_matrix(results):
    """Which evidence location was found in which experiment.

    Returns (experiment ids, rows), rows = [((component, file, line, api), {ids that found it}), ...].
    """
    finished = [r for r in results if r["state"] in ("ok", "empty")]
    ids = [r["name"].split("-")[0] for r in finished]
    found = {}
    for r, short in zip(finished, ids):
        for name, evidence in r["assets"]:
            for file, line, api in evidence:
                found.setdefault((name, file, line, api), set()).add(short)
    return ids, sorted(found.items())


def write_reports(results):
    """evidence.csv (one row per finding) and comparison.md (experiments side by side)."""
    import csv
    with open(RESULTS_DIR / "evidence.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["experiment", "component", "file", "line", "api_call"])
        for r in results:
            for name, evidence in r["assets"]:
                for file, line, api in evidence:
                    writer.writerow([r["name"], name, file, line, api])

    ids, rows = evidence_matrix(results)
    lines = ["# Experiments", "", "| id | experiment | components | evidence | question |", "|---|---|---|---|---|"]
    for r in results:
        lines.append(f"| {r['name'].split('-')[0]} | {r['name']} | {r['count']} | {r.get('locations', '-')} | {r['description']} |")
    lines += ["", "# Evidence found per experiment", "",
              "| component | location | api call | " + " | ".join(ids) + " |",
              "|---|---|---|" + "---|" * len(ids)]
    for (name, file, line, api), found_in in rows:
        lines.append(f"| {name} | {file}:{line} | {api} | " + " | ".join("yes" if i in found_in else "-" for i in ids) + " |")
    (RESULTS_DIR / "comparison.md").write_text("\n".join(lines) + "\n")


def print_summary(results, started):
    print(f"\n{cyan(RULE * 2)} {bold('Summary')}")
    print(f"   {dim('overall')} {bar(1, 1)} {dim('100%')}")
    if results:
        width = max(len(r["name"]) for r in results) + 2
        header = f"{'experiment':<{width}}{'components':<12}{'evidence':<10}{'time':<8}detected"
        print(f"\n   {dim('  ' + header)}")
        for r in results:
            icon, paint = {"ok": (OK, green), "empty": (WARN, yellow)}.get(r["state"], (BAD, red))
            note = r["note"][: max(10, WIDTH - width - 40)]
            print(f"   {paint(icon)} {r['name']:<{width}}{r['count']:<12}{str(r.get('locations', '-')):<10}"
                  f"{duration(r['seconds']):<8}{dim(note)}")

        ids, rows = evidence_matrix(results)
        if rows:
            print(f"\n   {bold('Evidence found')}  {dim('(' + OK + ' = detected in that experiment)')}")
            place_width = max(len(f"{f}:{l}") for (_, f, l, _), _ in rows) + 2
            print(f"   {dim(' ' * 11 + 'location'.ljust(place_width) + ''.join(i.ljust(4) for i in ids))}")
            for (name, file, line, api), found_in in rows:
                marks = "".join((green(OK) if i in found_in else dim("·")) + " " * (4 - 1) for i in ids)
                print(f"   {name:<11}{f'{file}:{line}':<{place_width}}{marks}{dim(api)}")
        write_reports(results)
        print(f"\n   {dim('results')}   {RESULTS_DIR}/<experiment>/cbom.json")
        print(f"   {dim('evidence')}  {RESULTS_DIR}/evidence.csv  and  comparison.md")
    print(f"   {dim('logs')}      {LOG_DIR}")
    print(f"   {dim('stop')}      (cd {PLUGIN_DIR} && docker compose down)")
    print(f"   {dim('total')}     {duration(time.time() - started)}\n")


def main():
    command = sys.argv[1] if len(sys.argv) > 1 else "all"
    if command not in ("all", "setup", "experiments"):
        sys.exit("usage: run.py [all|setup|experiments]")
    started = time.time()
    setup_steps = 6
    steps = Steps({"all": setup_steps + 1, "setup": setup_steps, "experiments": 1}[command] + (0 if command == "setup" else len(EXPERIMENTS)))

    print(f"\n  {bold('CBOM experiments  ·  Vanetza  ·  sonar-cryptography (CBOMkit)')}")
    print(f"  {dim('target')}   {VANETZA_ROOT}")
    print(f"  {dim('scope')}    {SCAN_SOURCES}  (excl. {SCAN_EXCLUSIONS})")
    print(f"  {dim('plugin')}   {PLUGIN_REPO[:-4]}  PR #{PLUGIN_PR} @ {PLUGIN_COMMIT}")
    print(f"  {dim('sonar')}    {SONAR_URL}")

    sonar, results = SonarQube(), []
    try:
        if command in ("all", "setup"):
            steps.start("Prerequisites");      check_prerequisites()
            steps.start("Plugin source");      prepare_plugin_source()
            steps.start("Build plugin");       build_plugin()
            steps.start("SonarQube server");   start_sonarqube(sonar)
            steps.start("SonarScanner CLI");   install_scanner()
            steps.start("Quality profile");    ok(f"profile {bold(QUALITY_PROFILE)} with {bold(RULE_KEY)} active  {dim('[' + sonar.ensure_profile() + ']')}")
        if command in ("all", "experiments"):
            results = run_experiments(steps, sonar)
    except Fail as error:
        print(f"\n   {red(BAD)} {red('error:')} {error}", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as error:
        print(f"\n   {red(BAD)} {red('error:')} command failed (exit {error.returncode}): {' '.join(map(str, error.cmd))}", file=sys.stderr)
        sys.exit(1)
    except OSError as error:  # includes network errors from urllib
        print(f"\n   {red(BAD)} {red('error:')} {error}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n   interrupted", file=sys.stderr)
        sys.exit(130)
    print_summary(results, started)


if __name__ == "__main__":
    main()