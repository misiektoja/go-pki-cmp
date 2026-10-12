//go:build integration

package cmptestsuite

import (
	"context"
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/stretchr/testify/require"
)

// cmpTestSuiteDir is the path to the cmp-test-suite checkout.
// Override with CMP_TEST_SUITE_DIR env var. Default is testdata/cmp-test-suite (run make setup-cmp-test-suite).
var cmpTestSuiteDir = envOrDefault("CMP_TEST_SUITE_DIR", "testdata/cmp-test-suite")

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// configData holds template variables for custom.robot.tmpl.
type configData struct {
	Port    int
	RAKey   string // PEM private key of the trusted registration authority
	RACert  string // PEM certificate of the trusted registration authority
	RAChain string // PEM chain from the RA certificate to the CA certificate
	CRLFile string // PEM CRL the CA serves, for the CRL update tests
}

// renderConfig renders the custom.robot.tmpl template into the config directory.
func renderConfig(t *testing.T, data configData) string {
	t.Helper()

	configDir, err := filepath.Abs("config")
	require.NoError(t, err)
	require.NoError(t, os.MkdirAll(configDir, 0755))

	tmplPath := filepath.Join(configDir, "custom.robot.tmpl")
	tmpl, err := template.ParseFiles(tmplPath)
	require.NoError(t, err)

	outPath := filepath.Join(configDir, "custom.robot")
	f, err := os.Create(outPath)
	require.NoError(t, err)
	defer f.Close()

	require.NoError(t, tmpl.Execute(f, data))
	t.Logf("rendered %s from %s", outPath, tmplPath)
	return configDir
}

// runOpts configures the cmp-test-suite run.
type runOpts struct {
	ConfigDir  string
	ReportsDir string
	Timeout    time.Duration
}

// runCMPTestSuite runs the cmp-test-suite using uv from a local checkout.
func runCMPTestSuite(t *testing.T, opts runOpts) error {
	t.Helper()

	if opts.Timeout == 0 {
		opts.Timeout = 14 * time.Minute
	}

	require.NoError(t, os.MkdirAll(opts.ReportsDir, 0755))

	// Verify cmp-test-suite directory exists.
	_, err := os.Stat(filepath.Join(cmpTestSuiteDir, "pyproject.toml"))
	require.NoError(t, err, "cmp-test-suite not found at %s (set CMP_TEST_SUITE_DIR)", cmpTestSuiteDir)

	// Link our config into the cmp-test-suite's config directory.
	for _, name := range []string{"custom.robot", "skip_tests.py"} {
		src := filepath.Join(opts.ConfigDir, name)
		dst := filepath.Join(cmpTestSuiteDir, "config", name)
		data, err := os.ReadFile(src)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(dst, data, 0644))
		t.Cleanup(func() { os.Remove(dst) })
	}

	// Build robot command arguments.
	args := []string{
		"run", "robot",
		"--argumentfile", filepath.Join(opts.ConfigDir, "args.robot"),
		"--outputdir", opts.ReportsDir,
		"tests/",
	}

	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "uv", args...)
	cmd.Dir = cmpTestSuiteDir
	cmd.Stdout = newPrefixWriter(os.Stdout, "[robot] ")
	cmd.Stderr = newPrefixWriter(os.Stdout, "[robot] ")

	t.Logf("exec: uv %s", strings.Join(args, " "))

	return cmd.Run()
}

func reportResults(t *testing.T, reportsDir string) {
	t.Helper()

	path := filepath.Join(reportsDir, "output.xml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Logf("warning: could not read output.xml: %v", err)
		return
	}

	var output robotOutput
	if err := xml.Unmarshal(data, &output); err != nil {
		t.Logf("warning: could not parse output.xml: %v", err)
		return
	}

	diags := extractDiagnostics(data)

	t.Log("")
	for i := range output.Suites {
		reportSuite(t, &output.Suites[i], "", diags)
	}

	for _, stat := range output.Statistics.Total.Stats {
		if stat.Text == "All Tests" {
			t.Logf("Robot Framework: %d passed, %d failed, %d skipped", stat.Pass, stat.Fail, stat.Skip)
		}
	}

	t.Log("")
}

func reportSuite(t *testing.T, suite *robotSuite, prefix string, diags map[string]string) {
	t.Helper()
	name := prefix + suite.Name

	// Check for suite setup failure.
	for _, kw := range suite.Keywords {
		if kw.Type == "setup" && kw.Status.Status == "FAIL" {
			t.Errorf("Suite setup failed: %s :: %s - %s", name, kw.Name, kw.Status.Text)
		}
	}

	// Log individual test failures.
	for _, test := range suite.Tests {
		if test.Status.Status == "FAIL" {
			if diag, ok := diags[test.Name]; ok {
				t.Errorf("FAIL: %s :: %s - %s [%s]", name, test.Name, test.Status.Text, diag)
			} else {
				t.Errorf("FAIL: %s :: %s - %s", name, test.Name, test.Status.Text)
			}
		}
	}

	for i := range suite.Suites {
		reportSuite(t, &suite.Suites[i], name+" :: ", diags)
	}
}

// Robot Framework output.xml structures.
type robotOutput struct {
	XMLName    xml.Name        `xml:"robot"`
	Suites     []robotSuite    `xml:"suite"`
	Statistics robotStatistics `xml:"statistics"`
}

type robotSuite struct {
	Name     string         `xml:"name,attr"`
	Keywords []robotKeyword `xml:"kw"`
	Tests    []robotTest    `xml:"test"`
	Suites   []robotSuite   `xml:"suite"`
}

type robotKeyword struct {
	Name   string      `xml:"name,attr"`
	Type   string      `xml:"type,attr"`
	Status robotStatus `xml:"status"`
}

type robotTest struct {
	Name   string      `xml:"name,attr"`
	Status robotStatus `xml:"status"`
}

type robotStatus struct {
	Status string `xml:"status,attr"`
	Text   string `xml:",chardata"`
}

type robotStatistics struct {
	Total robotStatTotal `xml:"total"`
}

type robotStatTotal struct {
	Stats []robotStat `xml:"stat"`
}

type robotStat struct {
	Text string `xml:",chardata"`
	Pass int    `xml:"pass,attr"`
	Fail int    `xml:"fail,attr"`
	Skip int    `xml:"skip,attr"`
}

// extractDiagnostics scans raw output.xml bytes and builds a map of
// test name → server StatusString for failed tests. This avoids modeling
// Robot Framework's complex nested XML schema (kw/if/branch/for/try/iter).
func extractDiagnostics(data []byte) map[string]string {
	result := make(map[string]string)
	content := string(data)

	for {
		start := strings.Index(content, "<test ")
		if start == -1 {
			break
		}
		end := strings.Index(content[start:], "</test>")
		if end == -1 {
			break
		}
		end += start + len("</test>")
		block := content[start:end]

		// Extract test name.
		nameStart := strings.Index(block, "name=\"")
		if nameStart == -1 {
			content = content[end:]
			continue
		}
		nameStart += len("name=\"")
		nameEnd := strings.Index(block[nameStart:], "\"")
		if nameEnd == -1 {
			content = content[end:]
			continue
		}
		testName := block[nameStart : nameStart+nameEnd]

		// Find StatusString within this test block.
		if idx := strings.Index(block, "StatusString:"); idx != -1 {
			lineEnd := strings.Index(block[idx:], "\n")
			if lineEnd == -1 {
				lineEnd = len(block) - idx
			}
			line := strings.TrimSpace(block[idx : idx+lineEnd])
			line = strings.TrimSuffix(line, "</msg>")
			result[testName] = line
		}

		content = content[end:]
	}
	return result
}
